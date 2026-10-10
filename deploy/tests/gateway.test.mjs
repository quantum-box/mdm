/*
 * Copyright (c) 2026 quantum-box
 * SPDX-License-Identifier: MIT
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  GatewayError,
  MAX_BODY_BYTES,
  MAX_RESPONSE_BYTES,
  canonicalRequest,
  extractCloudflareCertificate,
  extractLambdaCertificate,
  forwardToOrigin,
  handleCloudflareRequest,
  handleLambdaHttpApiV2,
  signGatewayRequest,
  stripUntrustedHeaders,
  bytesToBase64,
  base64ToBytes,
} from "../gateway/index.mjs";

const goldenVectors = JSON.parse(await readFile(new URL("../gateway/vectors.json", import.meta.url), "utf8"));
assert.ok(Array.isArray(goldenVectors) && goldenVectors.length > 0, "golden gateway vectors are required");
const golden = goldenVectors[0];
const key = "0123456789abcdef0123456789abcdef";
const nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const der = Uint8Array.from([0x30, 0x82, 0x01, 0x02, 0x04]);
const body = Uint8Array.from([0, 1, 2, 255]);

function fakeFetchFactory({ status = 200, body: responseBody = Uint8Array.from([9, 8, 7]), headers = { "content-type": "application/octet-stream", "x-apple-mdm-status": "Acknowledged" } } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return new Response(responseBody, { status, headers });
  };
  return { calls, fetchImpl };
}

function cloudflareRequest(cf, { path = "/mdm", method = "PUT", requestBody = body, headers = {} } = {}) {
  const input = new Headers(headers);
  return {
    url: `https://edge.example${path}`,
    method,
    headers: input,
    cf: { tlsClientAuth: cf },
    arrayBuffer: async () => requestBody.buffer.slice(requestBody.byteOffset, requestBody.byteOffset + requestBody.byteLength),
  };
}

function lambdaEvent({ cert = der, requestBody = body, path = "/mdm", method = "PUT", headers = { "content-type": "application/x-apple-aspen-mdm", "x-apple-mdm": "1" }, query = "a=%2F&b=" } = {}) {
  const clientCertPem = cert === null ? undefined : `-----BEGIN CERTIFICATE-----\n${bytesToBase64(cert)}\n-----END CERTIFICATE-----`;
  return {
    version: "2.0",
    routeKey: "$default",
    rawPath: path,
    rawQueryString: query,
    headers: {
      ...headers,
      // These must never become the trusted certificate or gateway envelope.
      "client-cert": "forged-header",
      "x-mdm-gateway-signature": "forged-signature",
    },
    body: bytesToBase64(requestBody),
    isBase64Encoded: true,
    requestContext: {
      http: { method },
      authentication: cert === null ? undefined : { clientCert: { clientCertPem } },
    },
  };
}

test("canonical vector preserves raw path/query and binary digests", async () => {
  const vectorBody = base64ToBytes(golden.body_base64);
  const vectorCertificate = golden.certificate_base64 ? base64ToBytes(golden.certificate_base64) : new Uint8Array();
  const canonical = await canonicalRequest({
    timestamp: golden.timestamp,
    nonce: golden.nonce,
    method: golden.method,
    rawPath: golden.target,
    body: vectorBody,
    certificateDer: vectorCertificate,
  });
  assert.equal(canonical, golden.canonical);
  assert.equal(canonical.endsWith("\n"), false);

  const signed = await signGatewayRequest({
    sharedKey: golden.key,
    timestamp: golden.timestamp,
    nonce: golden.nonce,
    method: golden.method,
    rawPath: golden.target,
    body: vectorBody,
    certificateDer: vectorCertificate,
  });
  assert.equal(signed.signature, golden.signature);
  assert.equal(signed.headers["x-mdm-gateway-certificate"], undefined);

  const changed = await signGatewayRequest({
    sharedKey: golden.key,
    timestamp: golden.timestamp,
    nonce: golden.nonce,
    method: "GET",
    rawPath: golden.target,
    body: vectorBody,
    certificateDer: vectorCertificate,
  });
  assert.notEqual(changed.signature, signed.signature);
  const changedBody = await signGatewayRequest({
    sharedKey: golden.key,
    timestamp: golden.timestamp,
    nonce: golden.nonce,
    method: golden.method,
    rawPath: golden.target,
    body: Uint8Array.from([0, 255, 42, 11]),
    certificateDer: vectorCertificate,
  });
  assert.notEqual(changedBody.signature, signed.signature);
  const changedPath = await signGatewayRequest({
    sharedKey: golden.key,
    timestamp: golden.timestamp,
    nonce: golden.nonce,
    method: golden.method,
    rawPath: "/mdm?x=a%2Bb&x=d",
    body: vectorBody,
    certificateDer: vectorCertificate,
  });
  assert.notEqual(changedPath.signature, signed.signature);
});

test("caller supplied identity and gateway headers are removed while Apple headers survive", () => {
  const headers = stripUntrustedHeaders({
    Authorization: "Bearer management-token",
    "X-Apple-MDM": "1",
    "Content-Type": "application/x-apple-aspen-mdm",
    "X-MDM-Gateway-Signature": "forged",
    "Client-Cert": "forged",
    "Client-Cert-Chain": "forged",
    "X-Forwarded-Client-Cert": "forged",
    "CF-Access-Client-Id": "forged",
    Host: "attacker.example",
  });
  assert.equal(headers.get("authorization"), "Bearer management-token");
  assert.equal(headers.get("x-apple-mdm"), "1");
  assert.equal(headers.get("content-type"), "application/x-apple-aspen-mdm");
  assert.equal(headers.has("x-mdm-gateway-signature"), false);
  assert.equal(headers.has("client-cert"), false);
  assert.equal(headers.has("x-forwarded-client-cert"), false);
  assert.equal(headers.has("cf-access-client-id"), false);
  assert.equal(headers.has("host"), false);
});

test("Cloudflare certificate metadata requires strict verified, unrevoked RFC9440 leaf", () => {
  const valid = {
    certPresented: "1",
    certVerified: "SUCCESS",
    certRevoked: "0",
    certRFC9440TooLarge: false,
    certChainRFC9440TooLarge: false,
    certRFC9440: `:${bytesToBase64(der)}:`,
  };
  const request = cloudflareRequest(valid);
  assert.deepEqual(Array.from(extractCloudflareCertificate(request)), Array.from(der));
  assert.equal(extractCloudflareCertificate(cloudflareRequest({ certPresented: "0" })), null);

  for (const patch of [
    { certPresented: "2" },
    { certVerified: "NONE" },
    { certRevoked: "1" },
    { certRevoked: "false" },
    { certRFC9440TooLarge: true },
    { certChainRFC9440TooLarge: true },
    { certRFC9440: ":not-base64!" },
  ]) {
    assert.throws(() => extractCloudflareCertificate(cloudflareRequest({ ...valid, ...patch })), (cause) => cause instanceof GatewayError && cause.status === 401);
  }
  const tooLarge = new Uint8Array(10 * 1024 + 1);
  assert.throws(() => extractCloudflareCertificate(cloudflareRequest({ ...valid, certRFC9440: `:${bytesToBase64(tooLarge)}:` })), /client_certificate_invalid/);
});

test("forwarding signs fixed origin request, retains raw query and binary body", async () => {
  const { fetchImpl, calls } = fakeFetchFactory();
  const response = await forwardToOrigin({
    method: "put",
    rawPath: "/mdm/%2Fdevice?x=a%2Fb&empty=",
    body,
    certificateDer: der,
    inputHeaders: {
      "Content-Type": "application/x-apple-aspen-mdm",
      "X-Apple-MDM": "1",
      Authorization: "Bearer token",
      "Accept-Encoding": "gzip",
      "X-MDM-Gateway-Version": "forged",
      "Client-Cert": "forged",
    },
    sharedKey: key,
    originUrl: "https://origin.example.invalid",
    accessClientId: "access-id",
    accessClientSecret: "access-secret",
    fetchImpl,
    nowMs: 1_700_000_000_000,
  });
  assert.equal(response.status, 200);
  assert.deepEqual(Array.from(new Uint8Array(await response.arrayBuffer())), [9, 8, 7]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://origin.example.invalid/mdm/%2Fdevice?x=a%2Fb&empty=");
  assert.deepEqual(Array.from(calls[0].init.body), Array.from(body));
  const sent = calls[0].init.headers;
  assert.equal(sent.get("x-mdm-gateway-version"), "1");
  assert.match(sent.get("x-mdm-gateway-signature"), /^[0-9a-f]{64}$/u);
  assert.equal(sent.get("x-mdm-gateway-certificate"), bytesToBase64(der));
  assert.equal(sent.get("x-apple-mdm"), "1");
  assert.equal(sent.get("authorization"), "Bearer token");
  assert.equal(sent.get("cf-access-client-id"), "access-id");
  assert.equal(sent.get("cf-access-client-secret"), "access-secret");
  assert.equal(sent.get("accept-encoding"), "identity");
  assert.equal(sent.has("client-cert"), false);
});

test("Worker and Lambda preserve the provider raw path and query bytes", async () => {
  const oldFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(null, { status: 204 });
  };
  try {
    const rawTarget = "/scep?x=a%2Bb&x=c";
    const worker = await handleCloudflareRequest(
      cloudflareRequest({ certPresented: "0" }, { path: rawTarget, method: "POST", requestBody: new Uint8Array() }),
      { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" },
    );
    assert.equal(worker.status, 204);
    const lambda = await handleLambdaHttpApiV2(
      lambdaEvent({ cert: null, path: "/scep", method: "POST", query: "x=a%2Bb&x=c", requestBody: new Uint8Array() }),
      { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" },
    );
    assert.equal(lambda.statusCode, 204);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, "https://origin.example.invalid/scep?x=a%2Bb&x=c");
    assert.equal(calls[1].url, "https://origin.example.invalid/scep?x=a%2Bb&x=c");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("URL normalization is rejected before a differently targeted origin request", async () => {
  const { fetchImpl, calls } = fakeFetchFactory();
  for (const rawPath of ["/scep/../scep", "/scep/./query", "/scep?"]) {
    await assert.rejects(
      forwardToOrigin({ method: "POST", rawPath, body, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl }),
      (cause) => cause instanceof GatewayError && cause.status === 400 && cause.code === "invalid_request_path",
    );
  }
  assert.equal(calls.length, 0);

  const worker = await handleCloudflareRequest(
    cloudflareRequest({ certPresented: "0" }, { path: "/scep/../scep", method: "POST", requestBody: new Uint8Array() }),
    { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" },
  );
  assert.equal(worker.status, 400);
  const lambda = await handleLambdaHttpApiV2(
    lambdaEvent({ cert: null, path: "/scep/../scep", method: "POST", query: "", requestBody: new Uint8Array() }),
    { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" },
  );
  assert.equal(lambda.statusCode, 400);
});

test("origin timeout remains active while a response body is stalled", { timeout: 1000 }, async () => {
  let cancelled = false;
  const stalledBody = new ReadableStream({
    cancel() {
      cancelled = true;
      return Promise.reject(new Error("cancel cleanup failed"));
    },
  });
  await assert.rejects(
    forwardToOrigin({
      method: "POST",
      rawPath: "/scep",
      body,
      sharedKey: key,
      originUrl: "https://origin.example.invalid",
      timeoutMs: 25,
      fetchImpl: async () => new Response(stalledBody, { status: 200 }),
    }),
    (cause) => cause instanceof GatewayError && cause.status === 504 && cause.code === "origin_timeout",
  );
  assert.equal(cancelled, true);
});

test("streaming origin responses stop at the byte cap", async () => {
  const chunk = new Uint8Array(Math.floor(MAX_RESPONSE_BYTES / 2) + 1);
  await assert.rejects(
    forwardToOrigin({
      method: "POST",
      rawPath: "/scep",
      body,
      sharedKey: key,
      originUrl: "https://origin.example.invalid",
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(chunk);
          controller.enqueue(chunk);
          controller.close();
        },
        cancel() {
          return Promise.reject(new Error("oversize cleanup failed"));
        },
      }), { status: 200 }),
    }),
    (cause) => cause instanceof GatewayError && cause.status === 502 && cause.code === "origin_response_too_large",
  );
});

test("device paths require a verified certificate while SCEP can be anonymous", async () => {
  const edgeDenied = await handleCloudflareRequest(
    cloudflareRequest({ certPresented: "0" }),
    { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" },
  );
  assert.equal(edgeDenied.status, 401);

  const { fetchImpl, calls } = fakeFetchFactory({ body: new Uint8Array() });
  await assert.rejects(
    forwardToOrigin({ method: "PUT", rawPath: "/mdm", body, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl }),
    (cause) => cause instanceof GatewayError && cause.status === 401 && cause.code === "client_certificate_required",
  );
  const response = await forwardToOrigin({ method: "POST", rawPath: "/scep?operation=PKIOperation", body, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.has("x-mdm-gateway-certificate"), false);
});

test("health stays a small no-store edge response and body limit is enforced", async () => {
  const health = await handleCloudflareRequest({ url: "https://edge.example/health", method: "GET", headers: new Headers(), arrayBuffer: async () => new ArrayBuffer(0) }, {});
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.deepEqual(await health.json(), { status: "ok", gateway: "ok" });

  const oversized = new Uint8Array(MAX_BODY_BYTES + 1);
  await assert.rejects(
    forwardToOrigin({ method: "POST", rawPath: "/scep", body: oversized, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl: fakeFetchFactory().fetchImpl }),
    (cause) => cause instanceof GatewayError && cause.status === 413,
  );
  const streamRequest = cloudflareRequest({ certPresented: "0" }, { path: "/scep", method: "POST", requestBody: new Uint8Array() });
  streamRequest.body = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(MAX_BODY_BYTES + 1));
      controller.close();
    },
  });
  const streamed = await handleCloudflareRequest(streamRequest, { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" });
  assert.equal(streamed.status, 413);
});

test("origin redirects are rejected and never followed", async () => {
  const { fetchImpl, calls } = fakeFetchFactory({ status: 302, headers: { location: "https://attacker.example" } });
  await assert.rejects(
    forwardToOrigin({ method: "POST", rawPath: "/scep", body, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl }),
    (cause) => cause instanceof GatewayError && cause.status === 502 && cause.code === "origin_redirect_rejected",
  );
  assert.equal(calls.length, 1);
});

test("origin responses with non-identity content encoding are rejected", async () => {
  const { calls, fetchImpl } = fakeFetchFactory({
    body: Uint8Array.from([0x1f, 0x8b, 0x08]),
    headers: { "content-encoding": "gzip" },
  });
  await assert.rejects(
    forwardToOrigin({ method: "POST", rawPath: "/scep", body, sharedKey: key, originUrl: "https://origin.example.invalid", fetchImpl }),
    (cause) => cause instanceof GatewayError && cause.status === 502 && cause.code === "origin_invalid_response_encoding",
  );
  assert.equal(calls[0].init.headers.get("accept-encoding"), "identity");
});

test("Lambda uses API Gateway client certificate context and preserves binary plist responses", async () => {
  const oldFetch = globalThis.fetch;
  const { fetchImpl, calls } = fakeFetchFactory({ body: Uint8Array.from([0, 255, 1]), headers: { "content-type": "application/xml", "x-apple-mdm-status": "Acknowledged" } });
  globalThis.fetch = fetchImpl;
  try {
    const result = await handleLambdaHttpApiV2(lambdaEvent(), { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" });
    assert.equal(result.statusCode, 200);
    assert.equal(result.isBase64Encoded, true);
    assert.deepEqual(Array.from(Uint8Array.from(atob(result.body), (character) => character.charCodeAt(0))), [0, 255, 1]);
    assert.equal(result.headers["x-apple-mdm-status"], "Acknowledged");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://origin.example.invalid/mdm?a=%2F&b=");
    assert.deepEqual(Array.from(calls[0].init.body), Array.from(body));
    assert.equal(calls[0].init.headers.get("x-apple-mdm"), "1");
    assert.equal(calls[0].init.headers.has("client-cert"), false);
    assert.equal(calls[0].init.headers.has("x-mdm-gateway-certificate"), true);
  } finally {
    globalThis.fetch = oldFetch;
  }

  const onlyHeaderCert = lambdaEvent({ cert: null });
  const certificate = extractLambdaCertificate(onlyHeaderCert);
  assert.equal(certificate, null);
});

test("Lambda health is local and binary errors are encoded safely", async () => {
  const health = await handleLambdaHttpApiV2({
    version: "2.0",
    rawPath: "/health",
    rawQueryString: "",
    headers: {},
    requestContext: { http: { method: "GET" } },
  }, {});
  assert.equal(health.statusCode, 200);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(health.body), (character) => character.charCodeAt(0)))), { status: "ok", gateway: "ok" });
});

test("Lambda rejects an invalid event and maps upstream failures to base64 safe JSON", async () => {
  const invalid = await handleLambdaHttpApiV2({ version: "1.0", body: "" }, { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" });
  assert.equal(invalid.statusCode, 400);
  assert.equal(invalid.isBase64Encoded, true);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(invalid.body), (character) => character.charCodeAt(0)))), { error: "unsupported_lambda_event" });

  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("redirect", { status: 302, headers: { location: "https://attacker.example" } });
  try {
    const result = await handleLambdaHttpApiV2(lambdaEvent({ cert: null, path: "/scep", method: "POST" }), { MDM_GATEWAY_KEY: key, MDM_ORIGIN_URL: "https://origin.example.invalid" });
    assert.equal(result.statusCode, 502);
    assert.equal(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(result.body), (character) => character.charCodeAt(0)))).error, "origin_redirect_rejected");
  } finally {
    globalThis.fetch = oldFetch;
  }
});
