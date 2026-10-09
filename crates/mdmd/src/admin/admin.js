/*
 * mdmd administrator console.
 *
 * This file intentionally has no framework or third-party dependency. The
 * bearer token lives only in `state.token` while this page is open. Dynamic
 * values are written with textContent or created as DOM nodes; no HTML from an
 * API response is interpreted by the browser.
 */
(function () {
  "use strict";

  const state = {
    token: "",
    devices: [],
    selectedDeviceId: "",
    jobs: new Map(),
    polling: new Set(),
    keyCache: new Map(),
    eraseIntent: null,
    adeDevices: [],
    adeCursor: null,
    commandCursor: null,
    commandHistoryDeviceId: "",
    observations: [],
  };

  const $ = (id) => document.getElementById(id);

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  function node(tag, value, className) {
    const element = document.createElement(tag);
    if (value !== undefined && value !== null) element.textContent = String(value);
    if (className) element.className = className;
    return element;
  }

  function clear(element) {
    while (element.firstChild) element.removeChild(element.firstChild);
  }

  function setNotice(element, message, kind) {
    element.textContent = message || "";
    if (kind) element.dataset.kind = kind;
    else delete element.dataset.kind;
  }

  function globalNotice(message, kind) {
    setNotice($("global-status"), message, kind);
  }

  function compactNotice(id, message, kind) {
    setNotice($(id), message, kind);
  }

  function errorMessage(error) {
    if (error instanceof ApiError) return `${error.message} (HTTP ${error.status})`;
    if (error && error.name === "AbortError") return "API応答がタイムアウトしました。状態を再取得してください。";
    return error && error.message ? error.message : "処理に失敗しました。";
  }

  function randomKey() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      const bytes = new Uint8Array(16);
      window.crypto.getRandomValues(bytes);
      return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (value && typeof value === "object") {
      const result = {};
      Object.keys(value).sort().forEach((key) => { result[key] = stableValue(value[key]); });
      return result;
    }
    return value;
  }

  function idempotencyContext(scope, payload) {
    const cacheKey = `${scope}|${JSON.stringify(stableValue(payload))}`;
    let key = state.keyCache.get(cacheKey);
    if (!key) {
      key = randomKey();
      state.keyCache.set(cacheKey, key);
    }
    return { cacheKey, key };
  }

  function clearIdempotency(context) {
    if (!context || !context.cacheKey) return;
    if (state.keyCache.get(context.cacheKey) === context.key) state.keyCache.delete(context.cacheKey);
  }

  function encodePath(value) {
    return encodeURIComponent(String(value));
  }

  async function request(path, options) {
    if (!state.token) throw new Error("先に管理APIトークンで接続してください。");
    const config = options || {};
    const headers = new Headers(config.headers || {});
    headers.set("Authorization", `Bearer ${state.token}`);
    let body;
    if (config.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(config.body);
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 20000);
    let response;
    try {
      response = await fetch(path, {
        method: config.method || "GET",
        headers,
        body,
        signal: config.signal || controller.signal,
        credentials: "same-origin",
      });
    } finally {
      window.clearTimeout(timeout);
    }
    const text = await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (_) { data = text; }
    }
    if (!response.ok) {
      const message = data && typeof data === "object" && typeof data.error === "string"
        ? data.error
        : "APIリクエストに失敗しました";
      throw new ApiError(message, response.status);
    }
    return data;
  }

  function selectedDevice() {
    return state.devices.find((device) => device.id === state.selectedDeviceId) || null;
  }

  function requireDevice() {
    const device = selectedDevice();
    if (!device) throw new Error("先に対象端末を選択してください。");
    return device;
  }

  function firstString(object, keys) {
    if (!object || typeof object !== "object") return "";
    for (const key of keys) {
      if (typeof object[key] === "string" && object[key]) return object[key];
    }
    return "";
  }

  function deviceLabel(device) {
    return firstString(device, ["device_name", "name", "serial_number", "serial"])
      || (device && device.state === "pending" ? "登録待ち端末" : "名称未取得");
  }

  function stateLabel(value) {
    const labels = {
      pending: "登録待ち",
      authenticated: "認証済み",
      active: "有効",
      revoked: "失効",
      queued: "配信待ち",
      awaiting_response: "端末応答待ち",
      deferred: "NotNow / 再試行待ち",
      completed: "ACK済み（反映未確認）",
      failed: "端末エラー",
      outcome_unknown: "結果不明・要確認",
      cancelled: "キャンセル済み",
    };
    return labels[value] || value || "不明";
  }

  function commandLabel(kind) {
    const labels = {
      device_information: "端末情報",
      install_profile: "プロファイルインストール",
      remove_profile: "プロファイル削除",
      declarative_management: "DDM同期",
      install_application: "アプリインストール",
      remove_application: "アプリ削除",
      installed_application_list: "インストール済みアプリ一覧",
      managed_application_list: "管理対象アプリ一覧",
      available_os_updates: "利用可能なOS更新",
      schedule_os_update: "OS更新の予約",
      os_update_status: "OS更新状態",
      device_lock: "端末ロック",
      erase_device: "端末消去",
      device_configured: "設定完了通知",
    };
    return labels[kind] || kind || "コマンド";
  }

  function pill(value) {
    return node("span", stateLabel(value), `state-pill ${String(value || "").replace(/[^a-z_]/g, "")}`);
  }

  function showJson(id, value) {
    const target = $(id);
    if (typeof value === "string") target.textContent = value;
    else {
      try { target.textContent = JSON.stringify(value, null, 2); }
      catch (_) { target.textContent = "表示できない応答です。"; }
    }
  }

  function renderSelectedDevice() {
    const target = $("selected-device");
    clear(target);
    const device = selectedDevice();
    if (!device) {
      target.className = "selected-device empty";
      target.textContent = "端末を選択してください。";
      return;
    }
    target.className = "selected-device";
    const fields = [
      ["端末名 / ID", deviceLabel(device)],
      ["シリアル", firstString(device, ["serial_number", "serial"]) || "未取得"],
      ["UDID", firstString(device, ["udid", "UDID"]) || "未取得"],
      ["OS", firstString(device, ["os_version", "osVersion"]) || "未取得"],
      ["状態", device.state || "unknown"],
      ["Push", device.push_ready ? "準備済み" : "未準備"],
      ["ADE設定待ち", device.awaiting_configuration ? "待機中" : "完了"],
    ];
    fields.forEach(([label, value]) => {
      const wrapper = node("div", undefined, "field");
      wrapper.append(node("strong", label), node("span", value));
      target.append(wrapper);
    });
  }

  function renderDeviceSelect() {
    const select = $("device-select");
    clear(select);
    select.append(node("option", "端末を選択"));
    select.firstChild.value = "";
    state.devices.forEach((device) => {
      const option = node("option", `${deviceLabel(device)} / ${device.id}`);
      option.value = device.id;
      option.selected = device.id === state.selectedDeviceId;
      select.append(option);
    });
  }

  function renderDevices(nextCursor) {
    const body = $("device-list");
    clear(body);
    if (!state.devices.length) {
      const row = node("tr");
      const cell = node("td", "端末がありません。", "empty");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
    } else {
      state.devices.forEach((device) => {
        const row = node("tr");
        const nameCell = node("td");
        nameCell.append(node("strong", deviceLabel(device)), node("span", device.id, "subline"));
        const serialCell = node("td", firstString(device, ["serial_number", "serial"]) || "未取得");
        const udidCell = node("td", firstString(device, ["udid", "UDID"]) || "未取得");
        const stateCell = node("td");
        stateCell.append(pill(device.state));
        const osCell = node("td", firstString(device, ["os_version", "osVersion"]) || "未取得");
        const actionCell = node("td");
        const button = node("button", "選択");
        button.type = "button";
        button.addEventListener("click", () => selectDevice(device.id));
        actionCell.append(button);
        row.append(nameCell, serialCell, udidCell, stateCell, osCell, actionCell);
        body.append(row);
      });
    }
    $("device-cursor").textContent = nextCursor ? `次のカーソル: ${nextCursor}` : "";
    renderDeviceSelect();
    renderSelectedDevice();
  }

  function selectDevice(id) {
    state.selectedDeviceId = id;
    const device = selectedDevice();
    if (device) {
      const serial = firstString(device, ["serial_number", "serial"]);
      $("vpp-serial").value = serial;
      $("vpp-status-serial").value = serial;
    }
    renderDeviceSelect();
    renderSelectedDevice();
    renderActivity();
    if (device) {
      void loadCommandHistory(device.id);
    } else {
      state.commandHistoryDeviceId = "";
      state.commandCursor = null;
      $("command-history-more").disabled = true;
      $("command-history-cursor").textContent = "端末を選択すると履歴を取得できます。";
    }
    setNotice($("global-status"), device ? `${deviceLabel(device)} を選択しました。` : "対象端末の選択を解除しました。", "success");
  }

  async function loadDevices() {
    const data = await request("/v1/enrollments");
    state.devices = Array.isArray(data && data.enrollments) ? data.enrollments : [];
    if (!state.devices.some((device) => device.id === state.selectedDeviceId)) state.selectedDeviceId = "";
    renderDevices(data && data.next_cursor);
    return data;
  }

  function downloadProfile(profile, id) {
    if (typeof profile !== "string") throw new Error("Enrollmentプロファイルが応答にありません。");
    const blob = new Blob([profile], { type: "application/x-apple-aspen-config" });
    const url = URL.createObjectURL(blob);
    const anchor = node("a", "");
    anchor.href = url;
    anchor.download = `mdm-enrollment-${id}.mobileconfig`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function createEnrollment() {
    compactNotice("profile-result", "Enrollmentを作成しています…", "working");
    try {
      const data = await request("/v1/enrollments", { method: "POST", body: {} });
      downloadProfile(data.profile, data.id || "new");
      compactNotice("profile-result", `Enrollment ${data.id || ""} を作成し、プロファイルをダウンロードしました。`, "success");
      await loadDevices();
    } catch (error) {
      compactNotice("profile-result", errorMessage(error), "error");
    }
  }

  function observationMatches(commandId) {
    return state.observations.some((row) => {
      if (!row || typeof row !== "object") return false;
      return row.command_id === commandId || row.commandId === commandId || row.command_uuid === commandId;
    });
  }

  function commandStatus(view, job) {
    if (view && view.state === "completed" && observationMatches(view.id)) return "実機反映確認（観測済み）";
    if (view && view.state) return stateLabel(view.state);
    return job && job.accepted ? "送信受付済み" : "処理中";
  }

  function renderActivity() {
    const target = $("command-activity");
    clear(target);
    const jobs = Array.from(state.jobs.values())
      .filter((job) => !state.selectedDeviceId || job.deviceId === state.selectedDeviceId)
      .sort((left, right) => (right.updatedAt || right.createdAt) - (left.updatedAt || left.createdAt))
      .slice(0, 24);
    if (!jobs.length) {
      target.append(node("p", "コマンドはまだありません。", "empty"));
      return;
    }
    jobs.forEach((job) => {
      const item = node("article", undefined, "activity-item");
      const text = node("div");
      text.append(node("p", job.label), node("p", `${job.id} / ${new Date(job.createdAt).toLocaleString("ja-JP")}`, "activity-meta"));
      const status = node("div", commandStatus(job.view, job), "activity-status");
      status.className = `activity-status state-pill ${String(job.view && job.view.state || "queued").replace(/[^a-z_]/g, "")}`;
      item.append(text, status);
      if (job.view && job.view.result) {
        const result = node("pre", undefined, "json-result");
        result.textContent = JSON.stringify(job.view.result, null, 2);
        item.append(result);
      }
      target.append(item);
    });
  }

  async function refreshCommand(id) {
    const job = state.jobs.get(id);
    if (!job) return;
    try {
      job.view = await request(`/v1/commands/${encodePath(id)}`);
      job.accepted = true;
      job.updatedAt = Number(job.view.updated_at || Date.now() / 1000) * 1000;
      renderActivity();
      const current = job.view && job.view.state;
      if (["completed", "failed", "cancelled", "outcome_unknown"].includes(current)) {
        state.polling.delete(id);
        if (["completed", "failed", "cancelled"].includes(current)) clearIdempotency(job.idempotency);
        return;
      }
    } catch (error) {
      job.lastError = errorMessage(error);
      renderActivity();
    }
    window.setTimeout(() => refreshCommand(id), 3000);
  }

  function trackCommand(id, label, deviceId, idempotency) {
    if (!id) return;
    const now = Date.now();
    const previous = state.jobs.get(id);
    state.jobs.set(id, {
      id,
      label,
      deviceId,
      createdAt: previous && previous.createdAt ? previous.createdAt : now,
      updatedAt: now,
      accepted: true,
      view: null,
      idempotency: idempotency || (previous && previous.idempotency) || null,
    });
    renderActivity();
    if (!state.polling.has(id)) {
      state.polling.add(id);
      void refreshCommand(id);
    }
  }

  function rememberCommand(view, deviceId) {
    if (!view || typeof view !== "object" || typeof view.id !== "string") return;
    const createdAt = Number(view.created_at || 0) * 1000 || Date.now();
    const updatedAt = Number(view.updated_at || 0) * 1000 || createdAt;
    const previous = state.jobs.get(view.id);
    state.jobs.set(view.id, {
      id: view.id,
      label: previous && previous.label ? previous.label : commandLabel(view.kind),
      deviceId: view.enrollment_id || deviceId,
      createdAt,
      updatedAt,
      accepted: true,
      view,
      idempotency: previous && previous.idempotency ? previous.idempotency : null,
    });
  }

  async function loadCommandHistory(deviceId, after) {
    try {
      if (!after) {
        state.commandHistoryDeviceId = deviceId;
        state.commandCursor = null;
      }
      const path = after
        ? `/v1/enrollments/${encodePath(deviceId)}/commands?after=${encodePath(after)}`
        : `/v1/enrollments/${encodePath(deviceId)}/commands`;
      const data = await request(path);
      const rows = Array.isArray(data && data.commands) ? data.commands : [];
      rows.forEach((view) => rememberCommand(view, deviceId));
      state.commandCursor = data && data.next_cursor ? data.next_cursor : null;
      $("command-history-more").disabled = !state.commandCursor;
      $("command-history-cursor").textContent = state.commandCursor
        ? `続きがあります（カーソル: ${state.commandCursor}）`
        : "最新の履歴まで取得済みです。";
      renderActivity();
    } catch (error) {
      $("command-history-more").disabled = true;
      $("command-history-cursor").textContent = errorMessage(error);
    }
  }

  async function enqueueCommand(label, command) {
    const device = requireDevice();
    const idempotency = idempotencyContext(`command:${device.id}`, command);
    globalNotice(`${label} を受付中…`, "working");
    const data = await request(`/v1/enrollments/${encodePath(device.id)}/commands`, {
      method: "POST",
      body: { idempotency_key: idempotency.key, command },
    });
    const id = data && (data.id || data.command_id);
    if (id) trackCommand(id, label, device.id, idempotency);
    globalNotice(`${label} は送信受付済みです。ACKと実機観測を待ちます。`, "success");
    return data;
  }

  async function runCommand(label, command) {
    try { await enqueueCommand(label, command); }
    catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  function optionalValue(id) {
    const value = $(id).value.trim();
    return value || null;
  }

  function numberValue(id, label) {
    const value = $(id).value.trim();
    if (!/^\d+$/.test(value)) throw new Error(`${label}は数字で入力してください。`);
    const number = Number(value);
    if (!Number.isSafeInteger(number)) throw new Error(`${label}が大きすぎます。`);
    return number;
  }

  function httpsValue(id) {
    const raw = $(id).value.trim();
    let url;
    try { url = new URL(raw); } catch (_) { throw new Error("Manifest URLが正しくありません。"); }
    if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new Error("Manifest URLは認証情報・fragmentのないHTTPS URLにしてください。");
    return url.toString();
  }

  function runDeviceInfo() {
    return runCommand("端末情報", {
      type: "device_information",
      queries: ["DeviceName", "OSVersion", "SerialNumber", "ModelName", "UDID", "IsSupervised"],
    });
  }

  function runDeviceConfigured() {
    return runCommand("設定完了通知", { type: "device_configured" });
  }

  function runInstalledApps() {
    return runCommand("インストール済みアプリ一覧", {
      type: "installed_application_list",
      identifiers: null,
      managed_apps_only: false,
      items: null,
    });
  }

  function runManagedApps() {
    return runCommand("管理対象アプリ一覧", { type: "managed_application_list", identifiers: null });
  }

  function runInstallAppStore() {
    try {
      const id = numberValue("app-store-id", "iTunes Store ID");
      const purchaseMethod = Number($("purchase-method").value);
      void runCommand("App Storeアプリのインストール", {
        type: "install_application",
        source: { AppStore: { itunes_store_id: id, purchase_method: purchaseMethod } },
      });
    } catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  function runInstallEnterprise() {
    try {
      const manifestUrl = httpsValue("manifest-url");
      void runCommand("Enterpriseアプリのインストール", {
        type: "install_application",
        source: { Enterprise: { manifest_url: manifestUrl } },
      });
    } catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  function runRemoveApp() {
    const identifier = $("remove-app-id").value.trim();
    if (!identifier) { globalNotice("Bundle IDを入力してください。", "error"); return; }
    void runCommand("アプリの削除", { type: "remove_application", identifier });
  }

  async function runKiosk(path, label, payload) {
    try {
      const device = requireDevice();
      const idempotency = idempotencyContext(`kiosk:${device.id}:${path}`, payload);
      globalNotice(`${label} を受付中…`, "working");
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/kiosk${path}`, {
        method: "POST", body: { ...payload, idempotency_key: idempotency.key },
      });
      const id = data && (data.id || data.command_id);
      if (id) trackCommand(id, label, device.id, idempotency);
      globalNotice(`${label} は送信受付済みです。ACKと実機観測を確認してください。`, "success");
    } catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  function applyKiosk() {
    const bundleId = $("kiosk-bundle-id").value.trim();
    if (!bundleId) { globalNotice("キオスクのBundle IDを入力してください。", "error"); return; }
    void runKiosk("", "キオスク適用", { bundle_id: bundleId });
  }

  function releaseKiosk() { void runKiosk("/release", "キオスク解除", {}); }

  function runOsAvailable() { void runCommand("利用可能なOS更新", { type: "available_os_updates" }); }
  function runOsStatus() { void runCommand("OS更新状態", { type: "os_update_status" }); }

  function runOsSchedule() {
    const productKey = optionalValue("os-product-key");
    const productVersion = optionalValue("os-product-version");
    if (!productKey && !productVersion) { globalNotice("ProductKeyまたはProductVersionを入力してください。", "error"); return; }
    void runCommand("OS更新の予約", {
      type: "schedule_os_update",
      updates: [{
        product_key: productKey,
        product_version: productVersion,
        install_action: $("os-install-action").value,
        max_user_deferrals: null,
        priority: null,
      }],
    });
  }

  function runLock() {
    void runCommand("端末ロック", {
      type: "device_lock",
      message: optionalValue("lock-message"),
      phone_number: optionalValue("lock-phone"),
      pin: optionalValue("lock-pin"),
    });
  }

  async function prepareErase() {
    try {
      const device = requireDevice();
      globalNotice("消去意図を作成しています…", "working");
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/erase-intents`, { method: "POST" });
      state.eraseIntent = { ...data, enrollment_id: device.id };
      const target = $("erase-intent");
      clear(target);
      target.className = "intent-box";
      target.append(
        node("strong", "この端末を消去します。"),
        node("p", `対象シリアル: ${data.serial_number || "未取得"}`),
        node("p", `有効期限: ${data.expires_at || "未取得"}`),
        node("p", "上のシリアル番号を入力して実行してください。"),
      );
      $("erase-confirm-serial").value = "";
      $("erase-execute").disabled = false;
      globalNotice("消去意図を作成しました。シリアル番号を確認してください。", "success");
    } catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  async function executeErase() {
    try {
      const intent = state.eraseIntent;
      const device = requireDevice();
      if (!intent || intent.enrollment_id !== device.id) throw new Error("先にこの端末の消去意図を作成してください。");
      const serial = $("erase-confirm-serial").value.trim();
      if (!serial || serial !== intent.serial_number) throw new Error("入力したシリアル番号が表示値と一致しません。");
      const payload = { intent_id: intent.id, token: intent.token, confirm_serial: serial };
      const idempotency = idempotencyContext(`erase:${device.id}`, payload);
      globalNotice("消去コマンドを受付中…", "working");
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/erase`, {
        method: "POST", body: { ...payload, idempotency_key: idempotency.key },
      });
      const id = data && (data.id || data.command_id);
      if (id) trackCommand(id, "端末消去", device.id, idempotency);
      globalNotice("消去コマンドは送信受付済みです。ACKだけで完了扱いにせず監査してください。", "success");
      $("erase-execute").disabled = true;
    } catch (error) { globalNotice(errorMessage(error), "error"); }
  }

  function serialList() {
    const checked = Array.from(document.querySelectorAll("#ade-device-list input[type=checkbox]:checked"))
      .map((input) => input.value).filter(Boolean);
    if (checked.length) return checked;
    return $("ade-serials").value.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
  }

  function renderAdeDevices(data) {
    state.adeDevices = Array.isArray(data && data.devices) ? data.devices : [];
    state.adeCursor = data && data.more_to_follow && data.cursor ? data.cursor : null;
    $("ade-sync").textContent = state.adeCursor ? "ADE同期を続行" : "Appleと同期";
    const target = $("ade-device-list");
    clear(target);
    if (!state.adeDevices.length) {
      target.append(node("p", "ADEデバイスがありません。", "empty"));
      return;
    }
    state.adeDevices.forEach((device) => {
      const serial = typeof device === "string" ? device : firstString(device, ["serial_number", "serialNumber", "serial"]);
      const label = typeof device === "string" ? device : (deviceLabel(device) || serial || "ADEデバイス");
      const row = node("label");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = serial;
      row.append(input, node("span", `${label}${serial ? ` / ${serial}` : ""}`));
      target.append(row);
    });
  }

  async function refreshAde() {
    try {
      const data = await request("/v1/ade/devices");
      renderAdeDevices(data);
      compactNotice("ade-result", "ADE一覧を取得しました。", "success");
    } catch (error) { compactNotice("ade-result", errorMessage(error), "error"); }
  }

  async function syncAde() {
    try {
      const body = state.adeCursor ? { cursor: state.adeCursor } : {};
      const data = await request("/v1/ade/sync", { method: "POST", body });
      renderAdeDevices(data);
      compactNotice(
        "ade-result",
        data && data.more_to_follow
          ? "ADE同期の1ページを取得しました。続行ボタンで残りを取得できます。"
          : "AppleとのADE同期が完了しました。",
        "success",
      );
    } catch (error) { compactNotice("ade-result", errorMessage(error), "error"); }
  }

  async function createAdeProfile() {
    try {
      const profile = JSON.parse($("ade-profile-json").value);
      if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("プロファイルはJSONオブジェクトで入力してください。");
      const idempotency = idempotencyContext("ade-profile", profile);
      const data = await request("/v1/ade/profiles", { method: "POST", body: { profile, idempotency_key: idempotency.key } });
      const uuid = data && (data.profile_uuid || data.uuid || data.ProfileUUID);
      if (uuid) $("ade-profile-uuid").value = uuid;
      compactNotice("ade-result", `ADEプロファイルを登録しました${uuid ? `（${uuid}）` : ""}。`, "success");
    } catch (error) { compactNotice("ade-result", errorMessage(error), "error"); }
  }

  async function assignAde(assign) {
    try {
      const profileUuid = $("ade-profile-uuid").value.trim();
      const devices = serialList();
      if (!profileUuid) throw new Error("Profile UUIDを入力してください。");
      if (!devices.length) throw new Error("割当対象のシリアル番号を選択または入力してください。");
      const payload = { profile_uuid: profileUuid, devices };
      const idempotency = idempotencyContext(`ade-${assign ? "assign" : "unassign"}`, payload);
      await request(assign ? "/v1/ade/assign" : "/v1/ade/unassign", { method: "POST", body: { ...payload, idempotency_key: idempotency.key } });
      clearIdempotency(idempotency);
      compactNotice("ade-result", assign ? "ADEプロファイル割当を受付しました。" : "ADEプロファイル割当解除を受付しました。", "success");
    } catch (error) { compactNotice("ade-result", errorMessage(error), "error"); }
  }

  async function changeLicense(assign) {
    try {
      const adamId = numberValue("vpp-adam-id", "adamId");
      const serialNumber = $("vpp-serial").value.trim();
      if (!serialNumber) throw new Error("シリアル番号を入力してください。");
      const payload = { adam_id: adamId, serial_number: serialNumber, assign };
      const idempotency = idempotencyContext("vpp-license", payload);
      const data = await request("/v1/apps/licenses", { method: "POST", body: { ...payload, idempotency_key: idempotency.key } });
      clearIdempotency(idempotency);
      compactNotice("vpp-result", `VPPライセンス${assign ? "割当" : "解除"}をAppleへ受付しました。eventIdを状態確認で追跡してください。`, "success");
      if (data && data.event_id) $("vpp-result").append(node("p", `eventId: ${data.event_id}`));
    } catch (error) { compactNotice("vpp-result", errorMessage(error), "error"); }
  }

  async function licenseStatus() {
    try {
      const adamId = numberValue("vpp-status-adam-id", "adamId");
      const serial = $("vpp-status-serial").value.trim();
      if (!serial) throw new Error("シリアル番号を入力してください。");
      const data = await request(`/v1/apps/licenses/${encodePath(adamId)}?serial=${encodePath(serial)}`);
      showJson("vpp-result", data);
      compactNotice("vpp-result", JSON.stringify(data, null, 2), "success");
    } catch (error) { compactNotice("vpp-result", errorMessage(error), "error"); }
  }

  function renderDeclarations(data) {
    const target = $("ddm-list");
    clear(target);
    const rows = Array.isArray(data && data.declarations) ? data.declarations : [];
    if (!rows.length) { target.append(node("p", "宣言がありません。", "empty")); return; }
    rows.forEach((row) => {
      const declaration = row && row.declaration ? row.declaration : row;
      const item = node("article", undefined, "declaration-item");
      const details = node("span");
      details.append(
        node("strong", declaration && (declaration.Identifier || declaration.identifier) || "識別子未取得"),
        node("span", ` / ${declaration && (declaration.Type || declaration.declaration_type) || "型未取得"}`, "subline"),
        node("span", row && row.deleted ? "削除済み" : "有効", "subline"),
      );
      const targets = declaration && (row.targets || declaration.targets);
      if (Array.isArray(targets)) details.append(node("span", `対象 ${targets.length}台`, "subline"));
      item.append(details);
      target.append(item);
    });
  }

  async function refreshDdm() {
    try {
      const data = await request("/v1/declarations");
      renderDeclarations(data);
      compactNotice("ddm-result", "DDM宣言一覧を取得しました。", "success");
    } catch (error) { compactNotice("ddm-result", errorMessage(error), "error"); }
  }

  async function enableDdm() {
    try {
      const device = requireDevice();
      const payload = {};
      const idempotency = idempotencyContext(`ddm-enable:${device.id}`, payload);
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/ddm/enable`, { method: "POST", body: { idempotency_key: idempotency.key } });
      const id = data && (data.id || data.command_id);
      if (id) trackCommand(id, "DDM有効化", device.id, idempotency);
      compactNotice("ddm-result", "DDM有効化を送信受付しました。", "success");
    } catch (error) { compactNotice("ddm-result", errorMessage(error), "error"); }
  }

  async function ddmStatus() {
    try {
      const device = requireDevice();
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/ddm/status?after=0`);
      compactNotice("ddm-result", JSON.stringify(data, null, 2), "success");
    } catch (error) { compactNotice("ddm-result", errorMessage(error), "error"); }
  }

  async function refreshObservations() {
    try {
      if (!state.selectedDeviceId) {
        state.observations = [];
        showJson("observations-result", "端末を選択すると実機観測を取得できます。");
        renderActivity();
        return null;
      }
      const device = requireDevice();
      const data = await request(`/v1/enrollments/${encodePath(device.id)}/observations`);
      state.observations = Array.isArray(data && data.observations)
        ? data.observations
        : (Array.isArray(data && data.records) ? data.records : []);
      showJson("observations-result", data);
      renderActivity();
    } catch (error) { showJson("observations-result", errorMessage(error)); }
  }

  async function refreshAudit() {
    try { showJson("audit-result", await request("/v1/audit?after=0")); }
    catch (error) { showJson("audit-result", errorMessage(error)); }
  }

  async function refreshIntegration() {
    try {
      const data = await request("/v1/integrations/apple");
      const target = $("integration-result");
      clear(target);
      const labels = {
        ade_configured: "ADE設定",
        ade_device_trust_configured: "ADE端末証明書",
        apns_configured: "APNs設定",
        apps_books_configured: "Apps & Books / VPP設定",
        device_acceptance: "実機受入",
      };
      if (data && typeof data === "object") {
        Object.keys(data).sort().forEach((key) => {
          const value = data[key];
          const displayValue = key === "device_acceptance"
            ? ({ unverified: "未検証" }[value] || String(value || "不明"))
            : (typeof value === "boolean" ? (value ? "有効" : "未設定") : value);
          const row = node("span", undefined, "subline");
          row.append(node("strong", `${labels[key] || key}: `), node("span", displayValue));
          target.append(row);
        });
      } else target.textContent = "応答を取得しました。";
      target.dataset.kind = "success";
    } catch (error) { compactNotice("integration-result", errorMessage(error), "error"); }
  }

  async function refreshAll() {
    if (!state.token) { globalNotice("先に管理APIトークンで接続してください。", "error"); return; }
    globalNotice("全体を更新しています…", "working");
    const results = await Promise.allSettled([loadDevices(), refreshAde(), refreshDdm(), refreshObservations(), refreshAudit(), refreshIntegration()]);
    const failures = results.filter((result) => result.status === "rejected");
    globalNotice(failures.length ? "一部の情報を更新できませんでした。各パネルの表示を確認してください。" : "全体を更新しました。", failures.length ? "error" : "success");
  }

  function connect() {
    state.token = $("api-token").value.trim();
    if (!state.token) { globalNotice("管理APIトークンを入力してください。", "error"); return; }
    void refreshAll();
  }

  function bind(id, event, handler) {
    const element = $(id);
    if (element) element.addEventListener(event, handler);
  }

  bind("connect-button", "click", connect);
  bind("api-token", "keydown", (event) => { if (event.key === "Enter") connect(); });
  bind("refresh-all", "click", refreshAll);
  bind("refresh-devices", "click", async () => { try { await loadDevices(); globalNotice("端末一覧を更新しました。", "success"); } catch (error) { globalNotice(errorMessage(error), "error"); } });
  bind("new-enrollment", "click", createEnrollment);
  bind("device-select", "change", (event) => selectDevice(event.target.value));
  bind("device-info", "click", runDeviceInfo);
  bind("device-configured", "click", runDeviceConfigured);
  bind("installed-apps", "click", runInstalledApps);
  bind("managed-apps", "click", runManagedApps);
  bind("install-app-store", "click", runInstallAppStore);
  bind("install-enterprise", "click", runInstallEnterprise);
  bind("remove-app", "click", runRemoveApp);
  bind("kiosk-apply", "click", applyKiosk);
  bind("kiosk-release", "click", releaseKiosk);
  bind("os-available", "click", runOsAvailable);
  bind("os-status", "click", runOsStatus);
  bind("os-schedule", "click", runOsSchedule);
  bind("device-lock", "click", runLock);
  bind("erase-prepare", "click", prepareErase);
  bind("erase-execute", "click", executeErase);
  bind("command-history-more", "click", () => {
    if (state.commandHistoryDeviceId && state.commandCursor) {
      void loadCommandHistory(state.commandHistoryDeviceId, state.commandCursor);
    }
  });
  bind("ade-refresh", "click", refreshAde);
  bind("ade-sync", "click", syncAde);
  bind("ade-profile-create", "click", createAdeProfile);
  bind("ade-assign", "click", () => assignAde(true));
  bind("ade-unassign", "click", () => assignAde(false));
  bind("vpp-assign", "click", () => changeLicense(true));
  bind("vpp-unassign", "click", () => changeLicense(false));
  bind("vpp-status", "click", licenseStatus);
  bind("ddm-refresh", "click", refreshDdm);
  bind("ddm-enable", "click", enableDdm);
  bind("ddm-status", "click", ddmStatus);
  bind("refresh-observations", "click", refreshObservations);
  bind("refresh-audit", "click", refreshAudit);
  bind("integration-health", "click", refreshIntegration);
})();
