/* SPDX-License-Identifier: MIT */
// CI runs this against the Linux release image; it never compiles Rust.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { signGatewayRequest } from "../gateway/index.mjs";

const image = process.argv[2] ?? "mdm:ci";
const name = `mdm-smoke-${randomBytes(6).toString("hex")}`;
const volume = `${name}-data`;
const directory = mkdtempSync(join(tmpdir(), "mdm-container-"));
const secrets = join(directory, "secrets");
const key = randomBytes(32).toString("hex");
const admin = randomBytes(32).toString("hex");
chmodSync(directory, 0o755);
mkdirSync(secrets, { mode: 0o755 });
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 60_000 });

function request(method, path, headers = {}) {
  // Pipe curl configuration so even synthetic tokens stay out of argv/logs.
  const config = [
    `url = ${JSON.stringify(`http://127.0.0.1:8080${path}`)}`,
    `request = ${JSON.stringify(method)}`,
    'silent', 'show-error', 'max-time = 3',
    'write-out = "\\nSTATUS:%{http_code}"',
    ...Object.entries(headers).map(([k, v]) => `header = ${JSON.stringify(`${k}: ${v}`)}`),
  ].join("\n");
  const output = execFileSync("docker", ["exec", "-i", name, "curl", "--config", "-"], {
    input: config, encoding: "utf8", timeout: 10_000, stdio: ["pipe", "pipe", "pipe"],
  });
  const split = output.lastIndexOf("\nSTATUS:");
  assert.ok(split >= 0, "container response includes a status");
  return { status: Number(output.slice(split + 8)), body: output.slice(0, split) };
}

async function ready() {
  for (let attempt = 0; attempt < 40; attempt++) {
    try { if (request("GET", "/health").status === 200) return; } catch { /* startup */ }
    await delay(500);
  }
  // Logs are categorical and contain no secret values.
  throw new Error(`container did not become ready:\n${docker("logs", name)}`);
}

async function signed(method, path, nonce, timestamp) {
  return (await signGatewayRequest({ sharedKey: key, method, rawPath: path, nonce, timestamp })).headers;
}

try {
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=MDM isolated container test", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", join(secrets, "ca.pem"),
    "-keyout", join(secrets, "ca-key.pem")], { stdio: "ignore" });
  writeFileSync(join(secrets, "gateway-key"), key);
  writeFileSync(join(secrets, "admin-token"), admin);
  for (const file of ["ca.pem", "ca-key.pem", "gateway-key", "admin-token"]) {
    // Isolated fixtures emulate read-only orchestration secret mounts.
    chmodSync(join(secrets, file), 0o444);
  }
  docker("volume", "create", volume);
  assert.equal(docker("image", "inspect", "--format", "{{.Config.User}}", image).trim(), "10001:10001");
  docker("run", "--detach", "--name", name,
    "--mount", `type=volume,source=${volume},target=/data`,
    "--mount", `type=bind,source=${secrets},target=/run/secrets,readonly`,
    "--tmpfs", "/run/mdmsecrets:rw,uid=10001,gid=10001,mode=0700",
    "-e", "MDM_PUBLIC_URL=https://device.example.invalid",
    "-e", "MDM_BOOTSTRAP_URL=https://bootstrap.example.invalid",
    "-e", "MDM_TOPIC=com.apple.mgmt.container-test",
    "-e", "MDM_ADMIN_TOKEN_FILE=/run/secrets/admin-token",
    "-e", "MDM_GATEWAY_KEY_FILE=/run/secrets/gateway-key", image);
  await ready();
  assert.equal(JSON.parse(docker("exec", name, "/usr/local/bin/mdmd-healthcheck")).status, "ok");
  assert.equal(docker("exec", name, "stat", "-c", "%a", "/run/mdmsecrets/gateway-key").trim(), "600");
  assert.equal(request("GET", "/scep?operation=GetCACaps").status, 401);
  assert.equal(request("GET", "/scep?operation=GetCACaps", await signed("GET", "/scep?operation=GetCACaps")).status, 200);

  // Keep the replay assertion within the validity window even during a slow
  // Docker restart; the container and test use the same host clock.
  const enrollmentHeaders = await signed("POST", "/v1/enrollments", undefined, String(Math.floor(Date.now() / 1000) + 25));
  enrollmentHeaders.authorization = `Bearer ${admin}`;
  const enrollment = request("POST", "/v1/enrollments", enrollmentHeaders);
  assert.equal(enrollment.status, 200);
  const created = JSON.parse(enrollment.body);
  assert.ok(created.profile.includes("https://bootstrap.example.invalid/scep"));
  assert.ok(created.profile.includes("https://device.example.invalid/checkin"));
  assert.ok(created.profile.includes("https://device.example.invalid/mdm"));
  assert.equal(request("POST", "/v1/enrollments", enrollmentHeaders).status, 409);

  docker("restart", name);
  await ready();
  // A freshly signed request with the persisted nonce is still a replay.
  const replay = await signed("POST", "/v1/enrollments", enrollmentHeaders["x-mdm-gateway-nonce"]);
  replay.authorization = `Bearer ${admin}`;
  assert.equal(request("POST", "/v1/enrollments", replay).status, 409);
  const listHeaders = await signed("GET", "/v1/enrollments");
  listHeaders.authorization = `Bearer ${admin}`;
  const listed = request("GET", "/v1/enrollments", listHeaders);
  assert.equal(listed.status, 200);
  assert.deepEqual(JSON.parse(listed.body).enrollments.map((item) => item.id), [created.id]);
  console.log("Container smoke passed: private secrets, signed gateway, split bootstrap, restart persistence.");
} finally {
  try { docker("rm", "--force", name); } catch { /* failed before creation */ }
  try { docker("volume", "rm", volume); } catch { /* failed before creation */ }
  rmSync(directory, { recursive: true, force: true });
}
