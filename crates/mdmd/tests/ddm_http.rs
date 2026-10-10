use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use mdmd::{
    config::Config,
    http::{App, AuthenticatedTlsPeer, router},
    identity::Identity,
    storage::{self, IssuedCertificate, Store},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::{MessageDigest, hash},
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use std::{fs, net::SocketAddr, sync::Arc};
use tempfile::{TempDir, tempdir};
use tower::util::ServiceExt;

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const READ_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UDID: &str = "00000000-0000-0000-0000-000000000201";

struct TestApp {
    _directory: TempDir,
    router: Router,
    store: Store,
}

struct RegisteredDevice {
    enrollment_id: String,
    fingerprint: String,
}

fn test_app() -> TestApp {
    let directory = tempdir().unwrap();
    let ca_cert = directory.path().join("ca.pem");
    let ca_key = directory.path().join("ca-key.pem");
    Identity::initialize(&ca_cert, &ca_key).unwrap();
    let identity = Arc::new(Identity::load(&ca_cert, &ca_key).unwrap());
    let database = directory.path().join("mdm.sqlite");
    let config = Config {
        database: database.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
        public_url: "https://mdm.example.test".into(),
        bootstrap_url: None,
        topic: "com.apple.mgmt.test".into(),
        organization: "Test Organization".into(),
        ca_cert,
        ca_key,
        apns_identity: None,
        admin_token: ADMIN_TOKEN.into(),
        read_token: Some(READ_TOKEN.into()),
        trust_proxy: true,
        gateway_key_file: None,
        tls_cert: None,
        tls_key: None,
    };
    config.validate().unwrap();
    let store = Store::open(&database).unwrap();
    let app = router(App {
        config,
        store: store.clone(),
        identity,
    });
    TestApp {
        _directory: directory,
        router: app,
        store,
    }
}

fn build_request(method: Method, uri: &str, token: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
    }
    builder.body(Body::from(body)).unwrap()
}

fn json_request(
    method: Method,
    uri: &str,
    token: Option<&str>,
    value: &serde_json::Value,
) -> Request<Body> {
    let mut request = build_request(method, uri, token, serde_json::to_vec(value).unwrap());
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    request
}

async fn send(app: &Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.unwrap()
}

fn ca_signed_certificate(app: &TestApp, common_name: &str) -> (String, String) {
    let ca_cert = X509::from_pem(&fs::read(app._directory.path().join("ca.pem")).unwrap()).unwrap();
    let ca_key =
        PKey::private_key_from_pem(&fs::read(app._directory.path().join("ca-key.pem")).unwrap())
            .unwrap();
    let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", common_name).unwrap();
    let subject = subject.build();
    let serial = Asn1Integer::from_bn(&BigNum::from_slice(&[2]).unwrap()).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&leaf_key).unwrap();
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
    builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let certificate = builder.build();
    let der = certificate.to_der().unwrap();
    let fingerprint = hex::encode(hash(MessageDigest::sha256(), &der).unwrap());
    (
        String::from_utf8(certificate.to_pem().unwrap()).unwrap(),
        fingerprint,
    )
}

fn self_signed_certificate() -> String {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", "unsigned-ddm-spoof")
        .unwrap();
    let subject = subject.build();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_slice(&[3]).unwrap()).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
}

fn percent_encoded_certificate(certificate: &str) -> HeaderValue {
    let encoded =
        percent_encoding::utf8_percent_encode(certificate, percent_encoding::NON_ALPHANUMERIC);
    HeaderValue::from_str(&encoded.to_string()).unwrap()
}

fn proxy_device_request(
    method: Method,
    uri: &str,
    body: Vec<u8>,
    certificate: &str,
) -> Request<Body> {
    let mut request = build_request(method, uri, None, body);
    request
        .headers_mut()
        .insert("x-mdm-client-verify", HeaderValue::from_static("SUCCESS"));
    request.headers_mut().insert(
        "x-mdm-client-cert",
        percent_encoded_certificate(certificate),
    );
    request
}

fn tls_router(app: &TestApp, fingerprint: &str) -> Router {
    app.router.clone().layer(Extension(AuthenticatedTlsPeer(
        Some(fingerprint.to_owned()),
        storage::now() + 3600,
    )))
}

fn register_active_device(app: &TestApp) -> RegisteredDevice {
    let challenge = "ddm-http-challenge";
    let enrollment_id = app
        .store
        .create_enrollment(challenge, storage::now())
        .unwrap();
    let (_certificate, fingerprint) = ca_signed_certificate(app, "ddm-http-device");
    app.store
        .issue_identity(challenge, "ddm-http-scep-request", storage::now(), |_id| {
            Ok(IssuedCertificate {
                fingerprint: fingerprint.clone(),
                expires_at: "2035-01-01T00:00:00Z".into(),
                response: Vec::new(),
            })
        })
        .unwrap();
    RegisteredDevice {
        enrollment_id,
        fingerprint,
    }
}

fn authenticate_xml_with_os(os_version: Option<&str>) -> Vec<u8> {
    let os_version = os_version
        .map(|version| format!("<key>OSVersion</key><string>{version}</string>"))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>Authenticate</string>
        <key>UDID</key><string>{UDID}</string>
        <key>Topic</key><string>com.apple.mgmt.test</string>
        <key>SerialNumber</key><string>SYNTHETIC-DDM</string>
        {os_version}
    </dict></plist>"#
    )
    .into_bytes()
}

fn authenticate_xml() -> Vec<u8> {
    authenticate_xml_with_os(Some("18.0"))
}

fn token_update_xml() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>TokenUpdate</string>
        <key>UDID</key><string>{UDID}</string>
        <key>Topic</key><string>com.apple.mgmt.test</string>
        <key>Token</key><data>AQIDBA==</data>
        <key>PushMagic</key><string>push-magic</string>
        <key>AwaitingConfiguration</key><false/>
    </dict></plist>"#
    )
    .into_bytes()
}

fn ddm_xml(endpoint: &str, data: Option<&[u8]>) -> Vec<u8> {
    let data = data
        .map(|data| format!("<key>Data</key><data>{}</data>", STANDARD.encode(data)))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>DeclarativeManagement</string>
        <key>Endpoint</key><string>{endpoint}</string>
        <key>UDID</key><string>{UDID}</string>
        {data}
    </dict></plist>"#
    )
    .into_bytes()
}

async fn enable_ddm(app: &TestApp, enrollment_id: &str) -> String {
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            &format!("/v1/enrollments/{enrollment_id}/ddm/enable"),
            Some(ADMIN_TOKEN),
            &serde_json::json!({"idempotency_key":"ddm-enable-http"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn declaration(identifier: &str, server_token: &str) -> serde_json::Value {
    serde_json::json!({
        "Type": "com.apple.activation.simple",
        "Identifier": identifier,
        "ServerToken": server_token,
        "Payload": {"StandardConfigurations": ["configuration-a"]}
    })
}

#[tokio::test]
async fn ddm_management_routes_enforce_roles() {
    let app = test_app();
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            "/v1/declarations",
            Some(READ_TOKEN),
            &declaration("ddm-role-declaration", "role-v1"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = send(
        &app.router,
        build_request(
            Method::GET,
            "/v1/declarations",
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(
        &app.router,
        json_request(
            Method::POST,
            "/v1/enrollments/missing/ddm/enable",
            Some(READ_TOKEN),
            &serde_json::json!({"idempotency_key":"role-enable"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn declarations_reject_unknown_top_level_keys() {
    let app = test_app();
    let mut value = declaration("ddm-unknown-key", "unknown-key-v1");
    value
        .as_object_mut()
        .unwrap()
        .insert("UnexpectedField".into(), serde_json::json!(true));
    let response = send(
        &app.router,
        json_request(Method::POST, "/v1/declarations", Some(ADMIN_TOKEN), &value),
    )
    .await;
    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn ddm_routes_require_a_ca_issued_device_identity() {
    let app = test_app();
    let response = send(
        &app.router,
        proxy_device_request(
            Method::PUT,
            "/checkin",
            authenticate_xml(),
            &self_signed_certificate(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let device = register_active_device(&app);
    let device_app = tls_router(&app, &device.fingerprint);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, authenticate_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, token_update_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let command_id = enable_ddm(&app, &device.enrollment_id).await;
    assert!(!command_id.is_empty());

    let response = send(
        &device_app,
        build_request(
            Method::PUT,
            "/checkin",
            None,
            ddm_xml("status", Some(br#"{"StatusItems":{},"Errors":[]}"#)),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );

    let response = send(
        &app.router,
        build_request(
            Method::GET,
            &format!(
                "/v1/enrollments/{}/ddm/status?after=0",
                device.enrollment_id
            ),
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ddm_rejects_invalid_json_and_returns_404_for_deleted_declarations() {
    let app = test_app();
    let device = register_active_device(&app);
    let device_app = tls_router(&app, &device.fingerprint);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, authenticate_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, token_update_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    enable_ddm(&app, &device.enrollment_id).await;

    let response = send(
        &device_app,
        build_request(
            Method::PUT,
            "/checkin",
            None,
            ddm_xml("status", Some(br#"{}"#)),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let declaration_id = "ddm-delete-declaration";
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            "/v1/declarations",
            Some(ADMIN_TOKEN),
            &declaration(declaration_id, "delete-v1"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &app.router,
        json_request(
            Method::PUT,
            &format!("/v1/declarations/{declaration_id}/targets"),
            Some(ADMIN_TOKEN),
            &serde_json::json!({"enrollment_ids":[device.enrollment_id]}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = send(
        &app.router,
        build_request(
            Method::DELETE,
            &format!("/v1/declarations/{declaration_id}?server_token=delete-v1"),
            Some(ADMIN_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = send(
        &device_app,
        build_request(
            Method::PUT,
            "/checkin",
            None,
            ddm_xml("declaration/activation/ddm-delete-declaration", None),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ddm_rejects_tokens_after_os_version_downgrade() {
    let app = test_app();
    let device = register_active_device(&app);
    let device_app = tls_router(&app, &device.fingerprint);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, authenticate_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &device_app,
        build_request(Method::PUT, "/checkin", None, token_update_xml()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    enable_ddm(&app, &device.enrollment_id).await;

    for os_version in [Some("15.0"), None] {
        let response = send(
            &device_app,
            build_request(
                Method::PUT,
                "/checkin",
                None,
                authenticate_xml_with_os(os_version),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = send(
            &device_app,
            build_request(Method::PUT, "/checkin", None, ddm_xml("tokens", None)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
