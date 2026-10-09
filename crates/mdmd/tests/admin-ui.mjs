import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test } from "node:test";
import vm from "node:vm";

const testsDirectory = dirname(fileURLToPath(import.meta.url));
const adminSource = readFileSync(join(testsDirectory, "../src/admin/admin.js"), "utf8");
const adminHtml = readFileSync(join(testsDirectory, "../src/admin/index.html"), "utf8");
const elementIds = [...adminHtml.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);

class FakeElement {
  constructor(tagName) {
    this.tagName = String(tagName).toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.dataset = {};
    this.className = "";
    this.value = "";
    this.disabled = false;
    this.selected = false;
    this.type = "";
    this.parentNode = null;
    this._textContent = "";
  }

  get firstChild() {
    return this.children[0] || null;
  }

  get textContent() {
    if (this._textContent) return this._textContent;
    return this.children.map((child) => child.textContent || "").join("");
  }

  set textContent(value) {
    this.children.forEach((child) => { child.parentNode = null; });
    this.children = [];
    this._textContent = value === undefined || value === null ? "" : String(value);
  }

  append(...items) {
    this._textContent = "";
    items.forEach((item) => {
      if (item === undefined || item === null) return;
      const child = item instanceof FakeElement ? item : new FakeElement("text");
      if (!(item instanceof FakeElement)) child.textContent = item;
      child.parentNode = this;
      this.children.push(child);
    });
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) {
      this.children.splice(index, 1);
      child.parentNode = null;
    }
    return child;
  }

  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }

  addEventListener(type, handler) {
    const handlers = this.listeners.get(type) || [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }

  dispatchEvent(event) {
    const current = event || { type: "" };
    if (!current.target) current.target = this;
    (this.listeners.get(current.type) || []).forEach((handler) => handler(current));
  }

  click() {
    this.dispatchEvent({ type: "click", target: this });
  }
}

class FakeDocument {
  constructor(ids) {
    this.elements = new Map(ids.map((id) => [id, new FakeElement("div")]));
    this.body = new FakeElement("body");
  }

  getElementById(id) {
    return this.elements.get(id) || null;
  }

  createElement(tagName) {
    return new FakeElement(tagName);
  }

  querySelectorAll() {
    return [];
  }
}

function jsonResponse(value, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => value === undefined ? "" : JSON.stringify(value),
  };
}

async function settle() {
  for (let index = 0; index < 12; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function createHarness({ commandState = "completed", failPostAttempts = [] } = {}) {
  const document = new FakeDocument(elementIds);
  const calls = [];
  const commands = [];
  let commandNumber = 0;
  let randomNumber = 0;
  const failures = new Set(failPostAttempts);

  const fetch = async (path, options = {}) => {
    const method = options.method || "GET";
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ path, method, body });

    if (path === "/v1/enrollments" && method === "GET") {
      return jsonResponse({
        enrollments: [{
          id: "enrollment-1",
          device_name: "検証用iPad",
          serial_number: "SERIAL-1",
          udid: "UDID-1",
          state: "active",
          push_ready: true,
          awaiting_configuration: false,
        }],
      });
    }
    if (path === "/v1/ade/devices") return jsonResponse({ devices: [] });
    if (path === "/v1/declarations") return jsonResponse({ declarations: [] });
    if (path === "/v1/audit?after=0") return jsonResponse({ records: [] });
    if (path === "/v1/integrations/apple") {
      return jsonResponse({
        ade_configured: false,
        ade_device_trust_configured: false,
        apps_books_configured: false,
        apns_configured: false,
        device_acceptance: "unverified",
      });
    }
    if (path === "/v1/enrollments/enrollment-1/commands" && method === "GET") {
      return jsonResponse({ commands: [], next_cursor: null });
    }
    if (path === "/v1/enrollments/enrollment-1/commands" && method === "POST") {
      if (failures.has(commands.length + 1)) throw new Error("simulated network failure");
      const id = `command-${++commandNumber}`;
      commands.push({ id, key: body.idempotency_key, command: body.command });
      return jsonResponse({ id, command_id: id });
    }
    const commandMatch = path.match(/^\/v1\/commands\/([^/?]+)$/);
    if (commandMatch && method === "GET") {
      const command = commands.find((entry) => entry.id === decodeURIComponent(commandMatch[1]));
      return jsonResponse({
        id: command && command.id,
        kind: command && command.command && command.command.type,
        state: commandState,
        updated_at: 1,
      });
    }
    throw new Error(`unexpected ${method} ${path}`);
  };

  const context = vm.createContext({
    AbortController,
    Blob,
    Headers,
    URL,
    console,
    document,
    fetch,
    setImmediate,
    window: {
      URL,
      crypto: { randomUUID: () => `ui-key-${++randomNumber}` },
      setTimeout,
      clearTimeout,
    },
  });
  vm.runInContext(adminSource, context, { filename: "admin.js" });

  document.getElementById("api-token").value = "test-admin-token";
  document.getElementById("connect-button").click();
  await settle();
  const deviceSelect = document.getElementById("device-select");
  deviceSelect.value = "enrollment-1";
  deviceSelect.dispatchEvent({ type: "change", target: deviceSelect });
  await settle();

  return { calls, commands, document };
}

function clickDeviceInformation(harness) {
  harness.document.getElementById("device-info").click();
  return settle();
}

function commandPosts(harness) {
  return harness.calls.filter((call) => call.method === "POST" && call.path.endsWith("/commands"));
}

test("端末情報は完了確認後に新しい冪等キーを発行する", async () => {
  const harness = await createHarness({ commandState: "completed" });

  await clickDeviceInformation(harness);
  await clickDeviceInformation(harness);

  const posts = commandPosts(harness);
  assert.equal(posts.length, 2);
  assert.notEqual(posts[0].body.idempotency_key, posts[1].body.idempotency_key);
  assert.deepEqual(posts[0].body.command, posts[1].body.command);
});

test("通信失敗時は再試行で同じ冪等キーを使う", async () => {
  const harness = await createHarness({ commandState: "completed", failPostAttempts: [1] });

  await clickDeviceInformation(harness);
  await clickDeviceInformation(harness);

  const posts = commandPosts(harness);
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body.idempotency_key, posts[1].body.idempotency_key);
});

test("結果不明のコマンドは再試行でも冪等キーを保持する", async () => {
  const harness = await createHarness({ commandState: "outcome_unknown" });

  await clickDeviceInformation(harness);
  await clickDeviceInformation(harness);

  const posts = commandPosts(harness);
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body.idempotency_key, posts[1].body.idempotency_key);
});
