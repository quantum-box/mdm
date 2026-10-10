/*
 * Copyright (c) 2026 quantum-box
 * SPDX-License-Identifier: MIT
 */

/**
 * The portable gateway envelope used by a public edge adapter and the Rust
 * origin.  This module deliberately uses only Web APIs: it runs in a
 * Cloudflare Worker and in Node.js Lambda without a provider SDK.
 */

export const GATEWAY_VERSION = "1";
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_CERTIFICATE_BYTES = 10 * 1024;
// Lambda HTTP API responses are base64 encoded and subject to a 6 MiB
// synchronous response limit. Keep the raw origin body below 4 MiB so the
// encoded body, headers, and response envelope remain below that limit.
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const TIMESTAMP_SKEW_SECONDS = 30;
export const ORIGIN_TIMEOUT_MS = 30_000;

const textEncoder = new TextEncoder();
const DEVICE_CERTIFICATE_PATHS = new Set(["/checkin", "/mdm"]);
const FORBIDDEN_INPUT_HEADERS = new Set([
  "client-cert",
  "client-cert-chain",
  "x-client-cert",
  "x-client-cert-chain",
  "x-forwarded-client-cert",
  "forwarded-client-cert",
  "cf-client-cert",
  "cf-client-cert-der",
  "cf-client-cert-der-base64",
  "cf-client-cert-sha256",
  "x-amzn-mtls-clientcert",
  "x-amzn-mtls-clientcert-subject",
  "x-amzn-mtls-clientcert-issuer",
  "x-amzn-mtls-clientcert-serial",
  "x-cert",
  "x-ssl-client-cert",
  "x-ssl-client-verify",
  "x-ssl-client-s-dn",
  "x-ssl-client-i-dn",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "forwarded",
  "host",
  "content-length",
  "accept-encoding",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "cf-connecting-ip",
  "cf-ray",
  "cf-visitor",
]);
const RESPONSE_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "set-cookie",
  "location",
]);
const RESPONSE_HEADER_ALLOWLIST = new Set([
  "content-type",
  "content-disposition",
  "etag",
  "last-modified",
  "retry-after",
]);

/** A safe error that can be returned to a caller without exposing internals. */
export class GatewayError extends Error {
  constructor(status, code) {
    super(code);
    this.name = "GatewayError";
    this.status = status;
    this.code = code;
  }
}

function error(status, code) {
  return new GatewayError(status, code);
}

function globalCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw error(500, "gateway_crypto_unavailable");
  }
  return globalThis.crypto;
}

function asBytes(value) {
  if (value === undefined || value === null) return new Uint8Array();
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw error(400, "invalid_body");
}

export function validateSharedKey(value) {
  if (typeof value !== "string" || value.length < 32 || value.length > 128) {
    throw error(500, "gateway_key_invalid");
  }
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code > 0x7f || code <= 0x20 || code === 0x7f) {
      throw error(500, "gateway_key_invalid");
    }
  }
  return value;
}

function validateTimestamp(value) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw error(400, "invalid_gateway_timestamp");
  }
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw error(400, "invalid_gateway_timestamp");
  }
  return value;
}

function validateNonce(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw error(400, "invalid_gateway_nonce");
  }
  return value;
}

function validateRawPath(value) {
  if (typeof value !== "string" || value.length === 0 || value[0] !== "/") {
    throw error(400, "invalid_request_path");
  }
  // A path is kept byte-for-byte in the signed envelope.  Reject delimiters
  // that could make a proxy reinterpret the request or a header value.
  if (
    value.startsWith("//") ||
    /[\u0000-\u0020\u007f#\\]/u.test(value) ||
    /%(?![0-9A-Fa-f]{2})/u.test(value) ||
    [...value].some((character) => character.charCodeAt(0) > 0x7f)
  ) {
    throw error(400, "invalid_request_path");
  }
  return value;
}

function validateMethod(value) {
  if (typeof value !== "string" || value.length === 0 || /[^!#$%&'*+.^_`|~0-9A-Za-z-]/u.test(value)) {
    throw error(400, "invalid_request_method");
  }
  return value.toUpperCase();
}

export function bytesToHex(bytes) {
  return Array.from(asBytes(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64(bytes) {
  const value = asBytes(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < value.length; offset += chunk) {
    binary += String.fromCharCode(...value.subarray(offset, offset + chunk));
  }
  if (typeof btoa !== "function") throw error(500, "gateway_crypto_unavailable");
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw error(400, "invalid_base64");
  }
  const firstPadding = value.indexOf("=");
  if (firstPadding >= 0 && firstPadding < value.length - 2) {
    throw error(400, "invalid_base64");
  }
  if (typeof atob !== "function") throw error(500, "gateway_crypto_unavailable");
  let decoded;
  try {
    decoded = atob(value);
  } catch {
    throw error(400, "invalid_base64");
  }
  const result = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  // atob() accepts a few non-canonical encodings.  Re-encode to make this
  // boundary deterministic and prevent two textual values for one signature.
  if (bytesToBase64(result) !== value) throw error(400, "invalid_base64");
  return result;
}

export async function sha256Hex(value) {
  const digest = await globalCrypto().subtle.digest("SHA-256", asBytes(value));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Return the exact UTF-8 string authenticated by the Rust origin.
 * There is intentionally no final newline.
 */
export async function canonicalRequest({ timestamp, nonce, method, rawPath, body = new Uint8Array(), certificateDer = new Uint8Array() }) {
  const timestampText = validateTimestamp(timestamp);
  const nonceText = validateNonce(nonce);
  const methodText = validateMethod(method);
  const pathText = validateRawPath(rawPath);
  const bodyBytes = asBytes(body);
  const certificateBytes = asBytes(certificateDer);
  const [bodyDigest, certificateDigest] = await Promise.all([
    sha256Hex(bodyBytes),
    sha256Hex(certificateBytes),
  ]);
  return [
    `mdm-gateway-v${GATEWAY_VERSION}`,
    timestampText,
    nonceText,
    methodText,
    pathText,
    bodyDigest,
    certificateDigest,
  ].join("\n");
}

async function hmacHex(key, message) {
  validateSharedKey(key);
  const cryptoApi = globalCrypto();
  const cryptoKey = await cryptoApi.subtle.importKey(
    "raw",
    textEncoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await cryptoApi.subtle.sign("HMAC", cryptoKey, textEncoder.encode(message));
  return bytesToHex(new Uint8Array(signature));
}

/**
 * Sign one origin request. Passing timestamp and nonce is useful for shared
 * vectors and tests; production forwarding leaves both unset.
 */
export async function signGatewayRequest({ sharedKey, method, rawPath, body = new Uint8Array(), certificateDer = new Uint8Array(), timestamp, nonce, nowMs = Date.now() }) {
  validateSharedKey(sharedKey);
  const timestampText = timestamp ?? String(Math.floor(nowMs / 1000));
  const nonceText = nonce ?? (() => {
    const value = new Uint8Array(32);
    globalCrypto().getRandomValues(value);
    return bytesToHex(value);
  })();
  const canonical = await canonicalRequest({
    timestamp: timestampText,
    nonce: nonceText,
    method,
    rawPath,
    body,
    certificateDer,
  });
  const signature = await hmacHex(sharedKey, canonical);
  const certificateBytes = asBytes(certificateDer);
  const headers = {
    "x-mdm-gateway-version": GATEWAY_VERSION,
    "x-mdm-gateway-timestamp": timestampText,
    "x-mdm-gateway-nonce": nonceText,
    "x-mdm-gateway-signature": signature,
  };
  if (certificateBytes.length > 0) {
    headers["x-mdm-gateway-certificate"] = bytesToBase64(certificateBytes);
  }
  return { headers, timestamp: timestampText, nonce: nonceText, signature, canonical };
}

function isForbiddenInputHeader(name) {
  const lower = name.toLowerCase();
  if (lower.startsWith("x-mdm-")) return true;
  if (lower.startsWith("cf-access-")) return true;
  if (
    lower.startsWith("x-cert-") ||
    lower.startsWith("x-ssl-client-") ||
    lower.startsWith("x-forwarded-") ||
    lower.startsWith("cf-")
  ) return true;
  return FORBIDDEN_INPUT_HEADERS.has(lower);
}

/** Copy caller headers while discarding every identity and hop-by-hop claim. */
export function stripUntrustedHeaders(input) {
  let source;
  try {
    source = new Headers(input ?? undefined);
  } catch {
    throw error(400, "invalid_request_headers");
  }
  const result = new Headers();
  for (const [name, value] of source.entries()) {
    if (!isForbiddenInputHeader(name)) result.set(name, value);
  }
  return result;
}

function validateAccessHeaders(accessClientId, accessClientSecret) {
  if ((accessClientId === undefined) !== (accessClientSecret === undefined)) {
    throw error(500, "gateway_access_credentials_incomplete");
  }
  if (accessClientId === undefined) return;
  if (typeof accessClientId !== "string" || typeof accessClientSecret !== "string" || accessClientId.length === 0 || accessClientSecret.length === 0 || /[\r\n]/u.test(accessClientId) || /[\r\n]/u.test(accessClientSecret)) {
    throw error(500, "gateway_access_credentials_invalid");
  }
}

export function validateOriginUrl(value) {
  if (typeof value !== "string" || value.length === 0) throw error(500, "origin_url_invalid");
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw error(500, "origin_url_invalid");
  }
  if (origin.protocol !== "https:" || !origin.hostname || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== "/") {
    throw error(500, "origin_url_invalid");
  }
  return origin;
}

function originTarget(origin, rawPath) {
  validateRawPath(rawPath);
  // URL(rawPath, origin) would treat //host as an authority.  The path
  // validator rejects that form; concatenation then retains the raw query.
  const targetText = `${origin.origin}${rawPath}`;
  try {
    const target = new URL(targetText);
    if (target.origin !== origin.origin) throw error(500, "origin_url_invalid");
    // WHATWG URL parsing normalizes dot segments and a bare query marker.
    // Refuse a target whose actual request target would differ from the
    // authenticated bytes sent to the origin.
    if (`${target.pathname}${target.search}` !== rawPath) {
      throw error(400, "invalid_request_path");
    }
    return targetText;
  } catch (cause) {
    if (cause instanceof GatewayError) throw cause;
    throw error(400, "invalid_request_path");
  }
}

export function isDeviceCertificatePath(rawPath) {
  try {
    const path = new URL(`https://gateway.invalid${rawPath}`).pathname;
    return DEVICE_CERTIFICATE_PATHS.has(path);
  } catch {
    return false;
  }
}

function gatewayResponse(status, code, headers = {}) {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...headers,
    },
  });
}

export function responseForError(cause) {
  if (cause instanceof GatewayError) return gatewayResponse(cause.status, cause.code);
  return gatewayResponse(502, "origin_unavailable");
}

export function localHealthResponse() {
  return new Response(JSON.stringify({ status: "ok", gateway: "ok" }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function requestBodyBytes(body) {
  const bytes = asBytes(body);
  if (bytes.length > MAX_BODY_BYTES) throw error(413, "request_body_too_large");
  return bytes;
}

function checkContentLength(headers) {
  const value = headers.get("content-length");
  if (value === null) return;
  if (!/^\d+$/u.test(value) || Number(value) > MAX_BODY_BYTES) throw error(413, "request_body_too_large");
}

function safeResponseHeaders(originHeaders) {
  const headers = new Headers();
  const source = new Headers(originHeaders ?? undefined);
  for (const [name, value] of source.entries()) {
    const lower = name.toLowerCase();
    if (RESPONSE_HOP_HEADERS.has(lower) || lower.startsWith("x-mdm-gateway-")) continue;
    if (RESPONSE_HEADER_ALLOWLIST.has(lower) || lower.startsWith("x-apple-")) headers.set(name, value);
  }
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

function responseContentLength(response) {
  let value;
  try {
    value = response?.headers?.get?.("content-length");
  } catch {
    throw error(502, "origin_invalid_response");
  }
  if (value === null || value === undefined) return;
  if (!/^\d+$/u.test(value) || Number(value) > MAX_RESPONSE_BYTES) {
    throw error(502, "origin_response_too_large");
  }
}

function readWithAbort(reader, signal) {
  if (signal?.aborted) return Promise.reject(error(504, "origin_timeout"));
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal?.removeEventListener("abort", onAbort);
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      try { void Promise.resolve(reader.cancel()).catch(() => {}); } catch { /* best effort */ }
      reject(error(504, "origin_timeout"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    let pending;
    try {
      pending = reader.read();
    } catch (cause) {
      if (settled) return;
      settled = true;
      cleanup();
      reject(cause);
      return;
    }
    Promise.resolve(pending).then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (cause) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(cause);
      },
    );
  });
}

/** Read an origin response with a byte cap while the request timeout remains active. */
async function readResponseBody(response, signal) {
  let contentEncoding;
  try {
    contentEncoding = response?.headers?.get?.("content-encoding");
  } catch {
    throw error(502, "origin_invalid_response");
  }
  if (contentEncoding !== null && contentEncoding !== undefined && contentEncoding.trim() !== "" && contentEncoding.trim().toLowerCase() !== "identity") {
    throw error(502, "origin_invalid_response_encoding");
  }
  responseContentLength(response);
  const stream = response?.body;
  if (!stream || typeof stream.getReader !== "function") {
    try {
      const bytes = new Uint8Array(await new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = () => signal?.removeEventListener("abort", onAbort);
        const onAbort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error(504, "origin_timeout"));
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        let pending;
        try {
          pending = response.arrayBuffer();
        } catch (cause) {
          if (settled) return;
          settled = true;
          cleanup();
          reject(cause);
          return;
        }
        Promise.resolve(pending).then(
          (value) => {
            if (settled) return;
            settled = true;
            cleanup();
            resolve(value);
          },
          (cause) => {
            if (settled) return;
            settled = true;
            cleanup();
            reject(cause);
          },
        );
      }));
      if (bytes.length > MAX_RESPONSE_BYTES) throw error(502, "origin_response_too_large");
      return bytes;
    } catch (cause) {
      if (signal?.aborted || (cause instanceof GatewayError && cause.code === "origin_timeout")) {
        throw error(504, "origin_timeout");
      }
      if (cause instanceof GatewayError) throw cause;
      throw error(502, "origin_invalid_response");
    }
  }

  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const item = await readWithAbort(reader, signal);
      if (item.done) break;
      const chunk = new Uint8Array(asBytes(item.value));
      total += chunk.length;
      if (total > MAX_RESPONSE_BYTES) {
        try { void Promise.resolve(reader.cancel()).catch(() => {}); } catch { /* best effort */ }
        throw error(502, "origin_response_too_large");
      }
      chunks.push(chunk);
    }
  } catch (cause) {
    if (signal?.aborted || (cause instanceof GatewayError && cause.code === "origin_timeout")) {
      throw error(504, "origin_timeout");
    }
    if (cause instanceof GatewayError && cause.code === "origin_response_too_large") throw cause;
    throw error(502, "origin_invalid_response");
  } finally {
    try { reader.releaseLock(); } catch { /* already released */ }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  if (signal?.aborted) throw error(504, "origin_timeout");
  return bytes;
}

function cancelResponseBody(response) {
  const body = response?.body;
  if (!body || typeof body.cancel !== "function") return;
  try { void Promise.resolve(body.cancel()).catch(() => {}); } catch { /* best effort */ }
}

/**
 * Sign and forward one request to a fixed HTTPS origin. This function performs
 * one fetch only; retries belong to the durable origin worker/outbox.
 */
export async function forwardToOrigin({
  method,
  rawPath,
  body = new Uint8Array(),
  certificateDer = new Uint8Array(),
  inputHeaders,
  sharedKey,
  originUrl,
  accessClientId,
  accessClientSecret,
  fetchImpl = globalThis.fetch,
  nowMs = Date.now(),
  timeoutMs = ORIGIN_TIMEOUT_MS,
}) {
  validateSharedKey(sharedKey);
  const origin = validateOriginUrl(originUrl);
  validateAccessHeaders(accessClientId, accessClientSecret);
  const methodText = validateMethod(method);
  const pathText = validateRawPath(rawPath);
  const target = originTarget(origin, pathText);
  const certificateBytes = asBytes(certificateDer);
  if (certificateBytes.length > MAX_CERTIFICATE_BYTES) throw error(401, "client_certificate_invalid");
  const headers = stripUntrustedHeaders(inputHeaders);
  checkContentLength(headers);
  const requestBody = await requestBodyBytes(body);
  if ((methodText === "GET" || methodText === "HEAD") && requestBody.length > 0) {
    throw error(400, "request_body_not_allowed");
  }
  if (isDeviceCertificatePath(pathText) && certificateBytes.length === 0) {
    throw error(401, "client_certificate_required");
  }
  // Apple plist/XML responses are byte-sensitive. Ask the origin and any
  // intermediary for identity encoding so fetch cannot transparently
  // decompress a representation whose content-encoding was stripped below.
  headers.set("accept-encoding", "identity");
  const signed = await signGatewayRequest({
    sharedKey,
    method: methodText,
    rawPath: pathText,
    body: requestBody,
    certificateDer: certificateBytes,
    nowMs,
  });
  for (const [name, value] of Object.entries(signed.headers)) headers.set(name, value);
  if (accessClientId !== undefined) {
    headers.set("cf-access-client-id", accessClientId);
    headers.set("cf-access-client-secret", accessClientSecret);
  }
  if (typeof fetchImpl !== "function") throw error(500, "gateway_fetch_unavailable");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let upstream;
  try {
    try {
      upstream = await fetchImpl(target, {
        method: methodText,
        headers,
        body: requestBody.length === 0 || methodText === "GET" || methodText === "HEAD" ? undefined : requestBody,
        redirect: "manual",
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) throw error(504, "origin_timeout");
      throw error(502, "origin_unavailable");
    }
    if (upstream.status >= 300 && upstream.status < 400) throw error(502, "origin_redirect_rejected");
    const responseBody = await readResponseBody(upstream, controller.signal);
    const emptyStatus = upstream.status === 204 || upstream.status === 205 || upstream.status === 304;
    return new Response(emptyStatus ? undefined : responseBody, {
      status: upstream.status,
      headers: safeResponseHeaders(upstream.headers ?? undefined),
    });
  } catch (cause) {
    // A redirect, malformed response, timeout, or size violation can leave
    // an upstream body unread. Cancel it before releasing the fetch timeout.
    cancelResponseBody(upstream);
    throw cause;
  } finally {
    // Keep this timer alive through complete response consumption. Clearing it
    // after fetch headers would allow a stalled body to run forever.
    clearTimeout(timer);
  }
}

function cloudflareAuth(request) {
  const auth = request?.cf?.tlsClientAuth;
  if (auth === undefined || auth === null) return null;
  if (auth.certPresented === "0") return null;
  if (auth.certPresented !== "1" || auth.certVerified !== "SUCCESS" || auth.certRevoked !== "0") {
    throw error(401, "client_certificate_invalid");
  }
  if (auth.certRFC9440TooLarge !== false || auth.certChainRFC9440TooLarge !== false) {
    throw error(401, "client_certificate_invalid");
  }
  if (typeof auth.certRFC9440 !== "string") {
    throw error(401, "client_certificate_invalid");
  }
  // Cloudflare exposes the RFC 9440 Structured Fields byte sequence as
  // `:<base64>:`. Accept the explicit `:base64:<base64>:` spelling as well
  // because some edge test fixtures and forwarding integrations use the
  // content-coding marker; both forms decode to the same DER bytes.
  let encoded = auth.certRFC9440;
  if (encoded.startsWith(":base64:")) {
    encoded = encoded.slice(8);
    if (encoded.endsWith(":")) encoded = encoded.slice(0, -1);
  } else if (encoded.startsWith(":") && encoded.endsWith(":")) {
    encoded = encoded.slice(1, -1);
  } else {
    throw error(401, "client_certificate_invalid");
  }
  let der;
  try {
    der = base64ToBytes(encoded);
  } catch {
    throw error(401, "client_certificate_invalid");
  }
  if (der.length === 0 || der.length > MAX_CERTIFICATE_BYTES) throw error(401, "client_certificate_invalid");
  return der;
}

/** Extract and validate Cloudflare's verified RFC 9440 leaf certificate. */
export function extractCloudflareCertificate(request) {
  return cloudflareAuth(request);
}

function pemToDer(pem) {
  if (typeof pem !== "string" || pem.length === 0 || pem.length > 128 * 1024) {
    throw error(401, "client_certificate_invalid");
  }
  const match = /-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----/u.exec(pem);
  if (!match) throw error(401, "client_certificate_invalid");
  let der;
  try {
    der = base64ToBytes(match[1].replace(/[\r\n\t ]/gu, ""));
  } catch {
    throw error(401, "client_certificate_invalid");
  }
  if (der.length === 0 || der.length > MAX_CERTIFICATE_BYTES) throw error(401, "client_certificate_invalid");
  return der;
}

/** Only API Gateway's authenticated client certificate context is trusted. */
export function extractLambdaCertificate(event) {
  const pem = event?.requestContext?.authentication?.clientCert?.clientCertPem;
  if (pem === undefined || pem === null || pem === "") return null;
  return pemToDer(pem);
}

async function readRequestBody(request) {
  let headers;
  try {
    headers = new Headers(request.headers ?? undefined);
  } catch {
    throw error(400, "invalid_request_headers");
  }
  checkContentLength(headers);
  const stream = request.body;
  if (stream && typeof stream.getReader === "function") {
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        const chunk = new Uint8Array(asBytes(item.value));
        total += chunk.length;
        if (total > MAX_BODY_BYTES) {
          try { await reader.cancel(); } catch { /* best effort */ }
          throw error(413, "request_body_too_large");
        }
        chunks.push(chunk);
      }
    } catch (cause) {
      if (cause instanceof GatewayError) throw cause;
      throw error(400, "invalid_request_body");
    } finally {
      try { reader.releaseLock(); } catch { /* already released */ }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  }
  let bytes;
  try {
    bytes = new Uint8Array(await request.arrayBuffer());
  } catch {
    throw error(400, "invalid_request_body");
  }
  return requestBodyBytes(bytes);
}

function requestRawPath(request) {
  const requestUrl = request?.url;
  let url;
  try {
    url = new URL(requestUrl);
  } catch {
    throw error(400, "invalid_request_path");
  }
  if (typeof requestUrl !== "string") throw error(400, "invalid_request_path");
  const authorityMarker = requestUrl.indexOf("://");
  if (authorityMarker < 0) throw error(400, "invalid_request_path");
  const authorityStart = authorityMarker + 3;
  const candidates = [
    requestUrl.indexOf("/", authorityStart),
    requestUrl.indexOf("?", authorityStart),
    requestUrl.indexOf("#", authorityStart),
  ].filter((index) => index >= 0);
  const pathStart = candidates.length === 0 ? requestUrl.length : Math.min(...candidates);
  let rawPath = requestUrl.slice(pathStart);
  if (rawPath.length === 0) rawPath = "/";
  else if (rawPath[0] === "?") rawPath = `/${rawPath}`;
  // Fragments are not sent in HTTP requests and URL parsing would silently
  // remove them. Reject before that normalization can change the signed path.
  validateRawPath(rawPath);
  if (`${url.pathname}${url.search}` !== rawPath) throw error(400, "invalid_request_path");
  return rawPath;
}

function envValue(env, key) {
  return env?.[key] ?? env?.vars?.[key];
}

/** Cloudflare Worker entry point. */
export async function handleCloudflareRequest(request, env = {}) {
  try {
    const method = request.method ?? "GET";
    const rawPath = requestRawPath(request);
    if (method.toUpperCase() === "GET" && rawPath === "/health") return localHealthResponse();
    const body = await readRequestBody(request);
    const certificateDer = extractCloudflareCertificate(request);
    const response = await forwardToOrigin({
      method,
      rawPath,
      body,
      certificateDer,
      inputHeaders: request.headers,
      sharedKey: envValue(env, "MDM_GATEWAY_KEY"),
      originUrl: envValue(env, "MDM_ORIGIN_URL"),
      accessClientId: envValue(env, "CF_ACCESS_CLIENT_ID"),
      accessClientSecret: envValue(env, "CF_ACCESS_CLIENT_SECRET"),
    });
    return response;
  } catch (cause) {
    return responseForError(cause);
  }
}

function lambdaRequestBody(event) {
  if (event?.body === undefined || event?.body === null || event.body === "") return new Uint8Array();
  if (typeof event.body !== "string") throw error(400, "invalid_request_body");
  if (event.isBase64Encoded === true) {
    // Reject an overlarge representation before atob allocates its decoded
    // buffer. Four encoded bytes represent at most three body bytes.
    if (event.body.length > Math.ceil(MAX_BODY_BYTES / 3) * 4) {
      throw error(413, "request_body_too_large");
    }
    return base64ToBytes(event.body);
  }
  if (event.body.length > MAX_BODY_BYTES) throw error(413, "request_body_too_large");
  return textEncoder.encode(event.body);
}

async function lambdaResponse(response) {
  const bytes = await readResponseBody(response, new AbortController().signal);
  return {
    statusCode: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: bytesToBase64(bytes),
    isBase64Encoded: true,
  };
}

/** AWS API Gateway HTTP API payload v2 adapter. */
export async function handleLambdaHttpApiV2(event, env = {}) {
  try {
    if (event?.version !== "2.0") throw error(400, "unsupported_lambda_event");
    const method = event.requestContext?.http?.method ?? event.httpMethod;
    if (typeof method !== "string") throw error(400, "invalid_request_method");
    const rawPath = event.rawPath;
    if (typeof rawPath !== "string" || rawPath.length === 0) throw error(400, "invalid_request_path");
    const rawQueryString = event.rawQueryString ?? "";
    if (typeof rawQueryString !== "string" || rawQueryString.startsWith("?") || /[\r\n]/u.test(rawQueryString)) throw error(400, "invalid_request_path");
    const signedPath = `${rawPath}${rawQueryString.length > 0 ? `?${rawQueryString}` : ""}`;
    if (method.toUpperCase() === "GET" && signedPath === "/health") {
      return await lambdaResponse(localHealthResponse());
    }
    const body = await requestBodyBytes(lambdaRequestBody(event));
    const certificateDer = extractLambdaCertificate(event);
    const response = await forwardToOrigin({
      method,
      rawPath: signedPath,
      body,
      certificateDer,
      inputHeaders: event.headers ?? {},
      sharedKey: envValue(env, "MDM_GATEWAY_KEY"),
      originUrl: envValue(env, "MDM_ORIGIN_URL"),
      accessClientId: envValue(env, "CF_ACCESS_CLIENT_ID"),
      accessClientSecret: envValue(env, "CF_ACCESS_CLIENT_SECRET"),
    });
    return await lambdaResponse(response);
  } catch (cause) {
    return await lambdaResponse(responseForError(cause));
  }
}
