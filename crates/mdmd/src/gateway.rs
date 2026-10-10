//! Authenticated gateway request envelope.
//!
//! A gateway terminates the public device TLS connection and forwards the
//! resulting HTTP request to `mdmd`.  The gateway therefore signs the exact
//! request bytes and, when present, forwards the device certificate leaf.  The
//! signature is deliberately checked before any certificate parsing so an
//! untrusted caller cannot use this endpoint as an OpenSSL parsing oracle.

use crate::{
    http::AuthenticatedTlsPeer,
    identity::Identity,
    storage::{self, Store, StoreError},
};
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{asn1::Asn1Time, x509::X509};
use sha2::{Digest, Sha256};
use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use subtle::ConstantTimeEq;

const VERSION: &str = "1";
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_CERT_DER: usize = 64 * 1024;
const MAX_HEADER: usize = 128;
const CLOCK_SKEW_SECONDS: i64 = 30;

const VERSION_HEADER: &str = "x-mdm-gateway-version";
const TIMESTAMP_HEADER: &str = "x-mdm-gateway-timestamp";
const NONCE_HEADER: &str = "x-mdm-gateway-nonce";
const CERTIFICATE_HEADER: &str = "x-mdm-gateway-certificate";
const SIGNATURE_HEADER: &str = "x-mdm-gateway-signature";

/// A validated gateway HMAC key.
#[derive(Clone)]
pub struct GatewayKey(Arc<[u8]>);

impl GatewayKey {
    /// Loads and validates a gateway key from a private regular file.
    ///
    /// A final LF or CRLF is accepted for operator-created secret files.  All
    /// other bytes must be printable ASCII, and the resulting key must be
    /// between 32 and 128 bytes.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("stat gateway key {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("gateway key must be a regular file");
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                bail!("gateway key must have file mode 0600");
            }
        }
        let mut key =
            fs::read(path).with_context(|| format!("read gateway key {}", path.display()))?;
        while matches!(key.last(), Some(b'\r' | b'\n')) {
            key.pop();
        }
        validate_key(&key)?;
        Ok(Self(Arc::from(key)))
    }

    fn sign(&self, message: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.0, message)
    }
}

/// Attaches the gateway middleware to an already stateful application router.
///
/// Keeping the router type at this boundary lets axum infer the concrete
/// middleware service without exposing an opaque `Layer` with unconstrained
/// associated service types to callers.
pub fn attach(router: Router, key: GatewayKey, store: Store, identity: Arc<Identity>) -> Router {
    router.layer(axum::middleware::from_fn(
        move |request: Request, next: Next| {
            let key = key.clone();
            let store = store.clone();
            let identity = identity.clone();
            async move { authenticate(key, store, identity, request, next).await }
        },
    ))
}

async fn authenticate(
    key: GatewayKey,
    store: Store,
    identity: Arc<Identity>,
    request: Request,
    next: Next,
) -> Response {
    if is_local_health(&request) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_BODY).await {
        Ok(body) => body,
        Err(_) => return gateway_error(StatusCode::PAYLOAD_TOO_LARGE, "gateway_body_too_large"),
    };
    let headers = &parts.headers;
    let version = match header_value(headers, VERSION_HEADER, MAX_HEADER) {
        Ok(Some(value)) => value,
        _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };
    if version != VERSION {
        return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
    }
    let timestamp_text = match header_value(headers, TIMESTAMP_HEADER, MAX_HEADER) {
        Ok(Some(value)) => value,
        _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };
    let timestamp = match parse_timestamp(timestamp_text) {
        Some(value) => value,
        None => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };
    let now = storage::now();
    if !within_clock_skew(timestamp, now) {
        return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
    }

    let nonce = match header_value(headers, NONCE_HEADER, MAX_HEADER) {
        Ok(Some(value)) if valid_lower_hex(value, 64) => value,
        _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };
    let certificate_b64 = match header_value(headers, CERTIFICATE_HEADER, MAX_CERT_DER * 2) {
        Ok(Some(value)) => value,
        Ok(None) => "",
        Err(_) => {
            return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
        }
    };
    let certificate_der = if certificate_b64.is_empty() {
        Vec::new()
    } else {
        match STANDARD.decode(certificate_b64) {
            Ok(value) if !value.is_empty() && value.len() <= MAX_CERT_DER => value,
            _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
        }
    };
    let signature = match header_value(headers, SIGNATURE_HEADER, 64) {
        Ok(Some(value)) if valid_lower_hex(value, 64) => match hex::decode(value) {
            Ok(value) if value.len() == 32 => value,
            _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
        },
        _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };

    let request_path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let canonical = canonical_request(
        &parts.method,
        timestamp_text,
        nonce,
        request_path,
        &body,
        &certificate_der,
    );
    let expected = key.sign(canonical.as_bytes());
    if expected.as_slice().ct_eq(&signature).unwrap_u8() != 1 {
        return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
    }

    let peer = if certificate_der.is_empty() {
        AuthenticatedTlsPeer(None, 0)
    } else {
        let certificate = match X509::from_der(&certificate_der) {
            Ok(value) => value,
            Err(_) => {
                return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
            }
        };
        match certificate.to_der() {
            Ok(value) if value == certificate_der => {}
            _ => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
        }
        let pem = match certificate.to_pem() {
            Ok(value) => value,
            Err(_) => {
                return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
            }
        };
        let fingerprint = match identity.verify_client_certificate(&pem) {
            Ok(value) => value,
            Err(_) => {
                return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
            }
        };
        let expires_at = match certificate_expiry(&certificate, storage::now()) {
            Ok(value) => value,
            Err(_) => {
                return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required");
            }
        };
        AuthenticatedTlsPeer(Some(fingerprint), expires_at)
    };

    let nonce_expiry = match nonce_expiry_for_timestamp(timestamp) {
        Some(value) => value,
        None => return gateway_error(StatusCode::UNAUTHORIZED, "gateway_authentication_required"),
    };
    if let Err(error) = store.claim_gateway_nonce(nonce, now, nonce_expiry) {
        if matches!(
            error.downcast_ref::<StoreError>(),
            Some(StoreError::Conflict)
        ) {
            return gateway_error(StatusCode::CONFLICT, "gateway_request_replayed");
        }
        tracing::error!(category = "gateway_nonce_storage_error");
        return gateway_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }

    parts.extensions.insert(peer);
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn is_local_health(request: &Request) -> bool {
    request.method() == Method::GET
        && request
            .uri()
            .path_and_query()
            .is_some_and(|value| value.as_str() == "/health")
        && request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|ConnectInfo(address)| address.ip().is_loopback())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str, max: usize) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.len() > max {
        return Err(());
    }
    Ok(Some(value))
}

fn parse_timestamp(value: &str) -> Option<i64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn within_clock_skew(timestamp: i64, now: i64) -> bool {
    let difference = if timestamp >= now {
        i128::from(timestamp) - i128::from(now)
    } else {
        i128::from(now) - i128::from(timestamp)
    };
    difference <= i128::from(CLOCK_SKEW_SECONDS)
}

fn nonce_expiry_for_timestamp(timestamp: i64) -> Option<i64> {
    timestamp.checked_add(CLOCK_SKEW_SECONDS + 1)
}

fn valid_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical_request(
    method: &Method,
    timestamp: &str,
    nonce: &str,
    request_path: &str,
    body: &[u8],
    certificate_der: &[u8],
) -> String {
    format!(
        "mdm-gateway-v1\n{timestamp}\n{nonce}\n{}\n{request_path}\n{}\n{}",
        method.as_str().to_ascii_uppercase(),
        hex::encode(Sha256::digest(body)),
        hex::encode(Sha256::digest(certificate_der)),
    )
}

fn certificate_expiry(certificate: &X509, now: i64) -> Result<i64> {
    let now_asn1 = Asn1Time::from_unix(now).context("get current gateway certificate time")?;
    let remaining = now_asn1
        .diff(certificate.not_after())
        .context("compare gateway certificate expiry")?;
    if remaining.days < 0 || remaining.secs < 0 {
        bail!("gateway certificate has expired");
    }
    let seconds = i64::from(remaining.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(remaining.secs)))
        .context("gateway certificate expiry is out of range")?;
    now.checked_add(seconds)
        .filter(|value| *value > now)
        .context("gateway certificate expiry is invalid")
}

fn validate_key(key: &[u8]) -> Result<()> {
    if !(32..=128).contains(&key.len())
        || key
            .iter()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("gateway key must be 32 to 128 printable ASCII bytes");
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = block;
    let mut outer_pad = block;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn gateway_error(status: StatusCode, error: &'static str) -> Response {
    let mut response = (status, axum::Json(serde_json::json!({"error": error}))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{canonical_request, hmac_sha256, nonce_expiry_for_timestamp, within_clock_skew};
    use axum::http::Method;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        key: String,
        timestamp: String,
        nonce: String,
        method: String,
        target: String,
        body_base64: String,
        certificate_base64: String,
        canonical: String,
        signature: String,
    }

    #[test]
    fn shared_gateway_vector_matches_canonical_and_signature() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../../deploy/gateway/vectors.json"))
                .expect("valid shared gateway vectors");
        for vector in vectors {
            let method = Method::from_bytes(vector.method.as_bytes()).expect("valid HTTP method");
            let body = STANDARD
                .decode(vector.body_base64)
                .expect("valid vector body");
            let certificate = STANDARD
                .decode(vector.certificate_base64)
                .expect("valid vector certificate");
            let canonical = canonical_request(
                &method,
                &vector.timestamp,
                &vector.nonce,
                &vector.target,
                &body,
                &certificate,
            );
            assert_eq!(canonical, vector.canonical);
            assert_eq!(
                hex::encode(hmac_sha256(vector.key.as_bytes(), canonical.as_bytes())),
                vector.signature
            );
        }
    }

    #[test]
    fn future_timestamp_nonce_remains_claimed_through_final_valid_second() {
        let timestamp = 1_030;
        let first_now = 1_000;
        let expiry = nonce_expiry_for_timestamp(timestamp).expect("timestamp has room for skew");
        assert_eq!(expiry, 1_061);
        assert!(within_clock_skew(timestamp, first_now + 60));
        assert!(!within_clock_skew(timestamp, first_now + 61));
        let store = crate::storage::Store::memory().expect("memory store");
        store
            .claim_gateway_nonce(
                "1111111111111111111111111111111111111111111111111111111111111111",
                first_now,
                expiry,
            )
            .expect("first request claims nonce");
        assert!(
            store
                .claim_gateway_nonce(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    first_now + 31,
                    expiry
                )
                .is_err()
        );
        assert!(
            store
                .claim_gateway_nonce(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    first_now + 60,
                    expiry
                )
                .is_err()
        );
    }
}
