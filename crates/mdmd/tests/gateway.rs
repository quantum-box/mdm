use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use mdmd::{
    config::Config,
    gateway::GatewayKey,
    http::{App, AuthenticatedTlsPeer, router_with_gateway},
    identity::Identity,
    storage::{self, Store},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::{TempDir, tempdir};
use tower::util::ServiceExt;

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GATEWAY_KEY: &[u8] = b"gateway-test-key-0123456789-abcdefghijk";

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    app: App,
    router: Router,
    identity: Arc<Identity>,
    ca_key: PathBuf,
    gateway_key: GatewayKey,
}

fn fixture() -> Fixture {
    let directory = tempdir().unwrap();
    let ca_cert = directory.path().join("ca.pem");
    let ca_key = directory.path().join("ca-key.pem");
    Identity::initialize(&ca_cert, &ca_key).unwrap();
    let identity = Arc::new(Identity::load(&ca_cert, &ca_key).unwrap());
    let key_path = directory.path().join("gateway.key");
    fs::write(&key_path, GATEWAY_KEY).unwrap();
    set_private_mode(&key_path);
    let gateway_key = GatewayKey::load(&key_path).unwrap();
    let database = directory.path().join("mdm.sqlite");
    let config = Config {
        database: database.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
        public_url: "https://mdm.example.test".into(),
        bootstrap_url: None,
        topic: "com.apple.mgmt.test".into(),
        organization: "Gateway Test".into(),
        ca_cert,
        ca_key: ca_key.clone(),
        apns_identity: None,
        admin_token: ADMIN_TOKEN.into(),
        read_token: None,
        trust_proxy: false,
        gateway_key_file: Some(key_path),
        tls_cert: None,
        tls_key: None,
    };
    config.validate().unwrap();
    let store = Store::open(&database).unwrap();
    let app = App {
        config,
        store,
        identity: identity.clone(),
    };
    let router = router_with_gateway(app.clone(), Some(gateway_key.clone()), None);
    Fixture {
        _directory: directory,
        database,
        app,
        router,
        identity,
        ca_key,
        gateway_key,
    }
}

fn set_private_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
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
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn signed_request(
    key: &[u8],
    method: Method,
    uri: &str,
    body: &[u8],
    timestamp: i64,
    nonce: &str,
    certificate_der: Option<&[u8]>,
) -> Request<Body> {
    let certificate = certificate_der.unwrap_or_default();
    let canonical = format!(
        "mdm-gateway-v1\n{timestamp}\n{nonce}\n{}\n{uri}\n{}\n{}",
        method.as_str().to_ascii_uppercase(),
        hex::encode(Sha256::digest(body)),
        hex::encode(Sha256::digest(certificate)),
    );
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-mdm-gateway-version", "1")
        .header("x-mdm-gateway-timestamp", timestamp.to_string())
        .header("x-mdm-gateway-nonce", nonce)
        .header(
            "x-mdm-gateway-signature",
            hex::encode(hmac_sha256(key, canonical.as_bytes())),
        )
        .body(Body::from(body.to_vec()))
        .unwrap();
    if let Some(certificate) = certificate_der {
        request.headers_mut().insert(
            "x-mdm-gateway-certificate",
            STANDARD.encode(certificate).parse().unwrap(),
        );
    }
    request
}

async fn send(router: &Router, request: Request<Body>) -> axum::response::Response {
    router.clone().oneshot(request).await.unwrap()
}

fn nonce(value: u64) -> String {
    format!("{value:064x}")
}

#[tokio::test]
async fn gateway_authenticates_signed_requests_and_persists_replay_state() {
    let fixture = fixture();
    let unsigned = Request::builder()
        .method(Method::GET)
        .uri("/scep?operation=GetCACaps")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&fixture.router, unsigned).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let first_nonce = nonce(1);
    let first = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        &[],
        storage::now(),
        &first_nonce,
        None,
    );
    assert_eq!(send(&fixture.router, first).await.status(), StatusCode::OK);

    let replay = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        &[],
        storage::now(),
        &first_nonce,
        None,
    );
    assert_eq!(
        send(&fixture.router, replay).await.status(),
        StatusCode::CONFLICT
    );

    let reopened = Store::open(&fixture.database).unwrap();
    assert!(
        reopened
            .claim_gateway_nonce(&first_nonce, storage::now(), storage::now() + 30)
            .is_err()
    );

    let admin_nonce = nonce(2);
    let mut admin = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/v1/enrollments",
        &[],
        storage::now(),
        &admin_nonce,
        None,
    );
    admin.headers_mut().insert(
        "authorization",
        format!("Bearer {ADMIN_TOKEN}").parse().unwrap(),
    );
    assert_eq!(send(&fixture.router, admin).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn gateway_binds_signature_to_request_and_suppresses_proxy_spoofing() {
    let fixture = fixture();
    let body = b"original";
    let timestamp = storage::now();

    let mut altered_path = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        body,
        timestamp,
        &nonce(10),
        None,
    );
    *altered_path.uri_mut() = "/scep?operation=GetCACert".parse().unwrap();
    assert_eq!(
        send(&fixture.router, altered_path).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let mut altered_body = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        body,
        timestamp,
        &nonce(11),
        None,
    );
    *altered_body.body_mut() = Body::from("altered");
    assert_eq!(
        send(&fixture.router, altered_body).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let mut altered_method = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        body,
        timestamp,
        &nonce(12),
        None,
    );
    *altered_method.method_mut() = Method::POST;
    assert_eq!(
        send(&fixture.router, altered_method).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let old = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        &[],
        timestamp - 31,
        &nonce(13),
        None,
    );
    assert_eq!(
        send(&fixture.router, old).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let mut altered_certificate = signed_request(
        GATEWAY_KEY,
        Method::GET,
        "/scep?operation=GetCACaps",
        &[],
        timestamp,
        &nonce(15),
        Some(&[1, 2]),
    );
    altered_certificate.headers_mut().insert(
        "x-mdm-gateway-certificate",
        STANDARD.encode([1, 3]).parse().unwrap(),
    );
    assert_eq!(
        send(&fixture.router, altered_certificate).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let mut spoof = signed_request(
        GATEWAY_KEY,
        Method::PUT,
        "/checkin",
        &[],
        timestamp,
        &nonce(14),
        None,
    );
    spoof
        .headers_mut()
        .insert("x-mdm-client-verify", "SUCCESS".parse().unwrap());
    spoof
        .headers_mut()
        .insert("x-mdm-client-cert", "spoofed".parse().unwrap());
    assert_eq!(
        send(&fixture.router, spoof).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let native_peer_router = router_with_gateway(
        fixture.app.clone(),
        Some(fixture.gateway_key.clone()),
        Some((
            AuthenticatedTlsPeer(Some("native-peer-that-must-not-win".into()), timestamp + 60),
            SocketAddr::from(([127, 0, 0, 1], 443)),
        )),
    );
    let request = signed_request(
        GATEWAY_KEY,
        Method::PUT,
        "/checkin",
        b"invalid",
        timestamp,
        &nonce(16),
        None,
    );
    assert_eq!(
        send(&native_peer_router, request).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn gateway_accepts_ca_client_certificate_and_rejects_unrelated_certificate() {
    let fixture = fixture();
    let (issued, unrelated) = certificates(&fixture.identity, &fixture.ca_key);
    let issued_request = signed_request(
        GATEWAY_KEY,
        Method::PUT,
        "/checkin",
        b"invalid",
        storage::now(),
        &nonce(20),
        Some(&issued.to_der().unwrap()),
    );
    assert_eq!(
        send(&fixture.router, issued_request).await.status(),
        StatusCode::BAD_REQUEST
    );

    let unrelated_request = signed_request(
        GATEWAY_KEY,
        Method::PUT,
        "/checkin",
        b"invalid",
        storage::now(),
        &nonce(21),
        Some(&unrelated.to_der().unwrap()),
    );
    assert_eq!(
        send(&fixture.router, unrelated_request).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn gateway_key_requires_private_file_mode() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("gateway.key");
    fs::write(&path, GATEWAY_KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(GatewayKey::load(&path).is_err());
    }
}

fn certificates(identity: &Identity, ca_key_path: &Path) -> (X509, X509) {
    let ca = X509::from_der(&identity.ca_der().unwrap()).unwrap();
    let ca_key = PKey::private_key_from_pem(&fs::read(ca_key_path).unwrap()).unwrap();
    let issued = signed_certificate(&ca, &ca_key, "issued", 2);
    let unrelated_ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let unrelated_ca = self_signed_ca(&unrelated_ca_key, "unrelated", 3);
    let unrelated = signed_certificate(&unrelated_ca, &unrelated_ca_key, "unrelated", 4);
    (issued, unrelated)
}

fn self_signed_ca(key: &PKey<Private>, common_name: &str, serial_number: u32) -> X509 {
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", common_name).unwrap();
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(serial_number).unwrap();
    let serial = Asn1Integer::from_bn(&serial_bn).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(key).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    let mut constraints = BasicConstraints::new();
    constraints.critical().ca();
    builder
        .append_extension(constraints.build().unwrap())
        .unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn signed_certificate(
    ca: &X509,
    ca_key: &PKey<Private>,
    common_name: &str,
    serial_number: u32,
) -> X509 {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", common_name).unwrap();
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(serial_number).unwrap();
    let serial = Asn1Integer::from_bn(&serial_bn).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(ca.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    builder
        .append_extension(constraints.build().unwrap())
        .unwrap();
    let mut usage = KeyUsage::new();
    usage.critical().digital_signature().key_encipherment();
    builder.append_extension(usage.build().unwrap()).unwrap();
    let mut eku = ExtendedKeyUsage::new();
    eku.client_auth();
    builder.append_extension(eku.build().unwrap()).unwrap();
    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    builder.build()
}
