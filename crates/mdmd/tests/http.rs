use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mdmd::{
    config::Config,
    http::{App, router},
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
use plist::Value;
use std::{fs, io::Cursor, net::SocketAddr, sync::Arc};
use tempfile::{TempDir, tempdir};
use tower::util::ServiceExt;

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const READ_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TestApp {
    _directory: TempDir,
    router: Router,
    store: Store,
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
        ca_cert: ca_cert.clone(),
        ca_key: ca_key.clone(),
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

fn validation_config(directory: &TempDir) -> Config {
    Config {
        database: directory.path().join("mdm.sqlite"),
        bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
        public_url: "https://mdm.example.test".into(),
        bootstrap_url: None,
        topic: "com.apple.mgmt.test".into(),
        organization: "Test Organization".into(),
        ca_cert: directory.path().join("ca.pem"),
        ca_key: directory.path().join("ca-key.pem"),
        apns_identity: None,
        admin_token: ADMIN_TOKEN.into(),
        read_token: Some(READ_TOKEN.into()),
        trust_proxy: true,
        gateway_key_file: None,
        tls_cert: None,
        tls_key: None,
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

async fn send(app: &Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.unwrap()
}

fn self_signed_certificate() -> String {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", "unsigned-spoof")
        .unwrap();
    let subject = subject.build();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_slice(&[1]).unwrap()).unwrap();
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

fn client_cert_header(pem: &str) -> HeaderValue {
    let encoded = percent_encoding::utf8_percent_encode(pem, percent_encoding::NON_ALPHANUMERIC);
    HeaderValue::from_str(&encoded.to_string()).unwrap()
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

fn device_request(method: Method, uri: &str, body: Vec<u8>, certificate: &str) -> Request<Body> {
    let mut request = build_request(method, uri, None, body);
    request
        .headers_mut()
        .insert("x-mdm-client-verify", HeaderValue::from_static("SUCCESS"));
    request
        .headers_mut()
        .insert("x-mdm-client-cert", client_cert_header(certificate));
    request
}

fn authenticate_xml(udid: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>Authenticate</string>
        <key>UDID</key><string>{udid}</string>
        <key>Topic</key><string>com.apple.mgmt.test</string>
        <key>SerialNumber</key><string>SYNTHETIC-HTTP</string>
        <key>OSVersion</key><string>18.0</string>
    </dict></plist>"#
    )
    .into_bytes()
}

fn token_update_xml(udid: &str, awaiting_configuration: bool) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>TokenUpdate</string>
        <key>UDID</key><string>{udid}</string>
        <key>Topic</key><string>com.apple.mgmt.test</string>
        <key>Token</key><data>AQIDBA==</data>
        <key>PushMagic</key><string>push-magic</string>
        <key>AwaitingConfiguration</key><{awaiting_configuration}/>
    </dict></plist>"#,
        awaiting_configuration = if awaiting_configuration {
            "true"
        } else {
            "false"
        },
    )
    .into_bytes()
}

fn response_xml(udid: &str, status: &str, command_uuid: Option<&str>) -> Vec<u8> {
    let command = command_uuid
        .map(|uuid| format!("<key>CommandUUID</key><string>{uuid}</string>"))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>UDID</key><string>{udid}</string>
        <key>Status</key><string>{status}</string>
        {command}
    </dict></plist>"#
    )
    .into_bytes()
}

#[tokio::test]
async fn bearer_roles_are_enforced() {
    let app = test_app();

    let response = send(
        &app.router,
        build_request(Method::GET, "/v1/enrollments", None, Vec::new()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = send(
        &app.router,
        build_request(Method::GET, "/v1/enrollments", Some(READ_TOKEN), Vec::new()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(
        &app.router,
        build_request(
            Method::GET,
            "/v1/enrollments",
            Some(ADMIN_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(
        &app.router,
        build_request(
            Method::POST,
            "/v1/enrollments",
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = send(
        &app.router,
        build_request(
            Method::POST,
            "/v1/enrollments",
            Some("wrong-token"),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn device_channel_requires_verified_certificate_headers() {
    let app = test_app();
    let checkin = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>CheckOut</string>
        <key>UDID</key><string>device</string>
    </dict></plist>"#
        .to_vec();

    let response = send(
        &app.router,
        build_request(Method::PUT, "/checkin", None, checkin.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut request = build_request(Method::PUT, "/checkin", None, checkin.clone());
    request
        .headers_mut()
        .insert("x-mdm-client-verify", HeaderValue::from_static("SUCCESS"));
    let response = send(&app.router, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut request = build_request(Method::PUT, "/checkin", None, checkin);
    request
        .headers_mut()
        .insert("x-mdm-client-verify", HeaderValue::from_static("SUCCESS"));
    request.headers_mut().insert(
        "x-mdm-client-cert",
        client_cert_header(&self_signed_certificate()),
    );
    let response = send(&app.router, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registered_device_completes_checkin_poll_and_command_ack() {
    let app = test_app();
    let udid = "00000000-0000-0000-0000-000000000101";
    let challenge = "http-pipeline-challenge";
    let enrollment_id = app
        .store
        .create_enrollment(challenge, storage::now())
        .unwrap();
    let (certificate, fingerprint) = ca_signed_certificate(&app, "http-pipeline-device");
    app.store
        .issue_identity(
            challenge,
            "http-pipeline-scep-request",
            storage::now(),
            |_id| {
                Ok(IssuedCertificate {
                    fingerprint: fingerprint.clone(),
                    expires_at: "2035-01-01T00:00:00Z".into(),
                    response: Vec::new(),
                })
            },
        )
        .unwrap();

    let response = send(
        &app.router,
        device_request(
            Method::PUT,
            "/checkin",
            authenticate_xml(udid),
            &certificate,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(
        &app.router,
        device_request(
            Method::PUT,
            "/checkin",
            token_update_xml(udid, true),
            &certificate,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        app.store
            .enrollments(None)
            .unwrap()
            .iter()
            .find(|e| e.id == enrollment_id)
            .unwrap()
            .awaiting_configuration
    );

    let response = send(
        &app.router,
        device_request(
            Method::PUT,
            "/checkin",
            token_update_xml(udid, false),
            &certificate,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut enqueue = build_request(
        Method::POST,
        &format!("/v1/enrollments/{enrollment_id}/commands"),
        Some(ADMIN_TOKEN),
        br#"{"idempotency_key":"http-pipeline-command","command":{"type":"device_information","queries":["UDID","OSVersion"]}}"#.to_vec(),
    );
    enqueue.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = send(&app.router, enqueue).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let command_id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = send(
        &app.router,
        device_request(
            Method::PUT,
            "/mdm",
            response_xml(udid, "Idle", None),
            &certificate,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let command = Value::from_reader(Cursor::new(body.as_ref())).unwrap();
    let command = command.as_dictionary().unwrap();
    assert_eq!(
        command.get("CommandUUID").and_then(Value::as_string),
        Some(command_id.as_str())
    );
    assert_eq!(
        command
            .get("Command")
            .and_then(Value::as_dictionary)
            .and_then(|command| command.get("RequestType"))
            .and_then(Value::as_string),
        Some("DeviceInformation")
    );

    let response = send(
        &app.router,
        device_request(
            Method::PUT,
            "/mdm",
            response_xml(udid, "Acknowledged", Some(&command_id)),
            &certificate,
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
            &format!("/v1/commands/{command_id}"),
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let command = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
    assert_eq!(command["state"], "completed");
    assert_eq!(command["enrollment_id"], enrollment_id);
}

#[tokio::test]
async fn enrollment_profile_is_uncached_and_has_exact_device_refs() {
    let app = test_app();
    let response = send(
        &app.router,
        build_request(
            Method::POST,
            "/v1/enrollments",
            Some(ADMIN_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let enrollment_id = json["id"].as_str().unwrap();
    let profile = json["profile"].as_str().unwrap();
    assert_eq!(json["challenge_expires_in_seconds"], 900);

    let root = Value::from_reader(Cursor::new(profile.as_bytes())).unwrap();
    let root = root.as_dictionary().unwrap();
    let payloads = root.get("PayloadContent").unwrap().as_array().unwrap();
    assert_eq!(payloads.len(), 3);
    let scep = payloads
        .iter()
        .find(|payload| {
            payload
                .as_dictionary()
                .and_then(|payload| payload.get("PayloadType"))
                .and_then(Value::as_string)
                == Some("com.apple.security.scep")
        })
        .unwrap()
        .as_dictionary()
        .unwrap();
    let scep_uuid = scep.get("PayloadUUID").unwrap().as_string().unwrap();
    let scep_content = scep.get("PayloadContent").unwrap().as_dictionary().unwrap();
    assert_eq!(
        scep_content.get("URL").and_then(Value::as_string),
        Some("https://mdm.example.test/scep")
    );
    assert_eq!(
        scep_content
            .get("Challenge")
            .and_then(Value::as_string)
            .map(str::len),
        Some(64)
    );
    let subject = scep_content.get("Subject").unwrap().as_array().unwrap();
    assert_eq!(
        subject[0].as_array().unwrap()[0].as_array().unwrap()[1].as_string(),
        Some(enrollment_id)
    );

    let mdm = payloads
        .iter()
        .find(|payload| {
            payload
                .as_dictionary()
                .and_then(|payload| payload.get("PayloadType"))
                .and_then(Value::as_string)
                == Some("com.apple.mdm")
        })
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(
        mdm.get("IdentityCertificateUUID")
            .and_then(Value::as_string),
        Some(scep_uuid)
    );
    assert_eq!(
        mdm.get("Topic").and_then(Value::as_string),
        Some("com.apple.mgmt.test")
    );
    assert_eq!(
        mdm.get("ServerURL").and_then(Value::as_string),
        Some("https://mdm.example.test/mdm")
    );
    assert_eq!(
        mdm.get("CheckInURL").and_then(Value::as_string),
        Some("https://mdm.example.test/checkin")
    );
    assert_eq!(
        mdm.get("AccessRights").and_then(Value::as_unsigned_integer),
        Some(4383)
    );
    assert!(mdm.get("ServerCapabilities").is_none());
}

#[tokio::test]
async fn request_limit_and_unsupported_bodies_are_rejected() {
    let app = test_app();
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut request = build_request(
        Method::POST,
        "/v1/enrollments/not-an-id/commands",
        Some(ADMIN_TOKEN),
        oversized,
    );
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = send(&app.router, request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let mut request = build_request(
        Method::POST,
        "/v1/enrollments/not-an-id/commands",
        Some(ADMIN_TOKEN),
        br#"{"idempotency_key":"test","command":{"type":"unsupported"}}"#.to_vec(),
    );
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let response = send(&app.router, request).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let mut request = build_request(
        Method::POST,
        "/v1/enrollments/not-an-id/commands",
        Some(ADMIN_TOKEN),
        b"not-json".to_vec(),
    );
    request
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    let response = send(&app.router, request).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn scep_get_rejects_an_oversized_encoded_message_before_decode() {
    let app = test_app();
    let encoded = "A".repeat(16 * 1024 + 1);
    let uri = format!("/scep?operation=PKIOperation&message={encoded}");
    let response = send(
        &app.router,
        build_request(Method::GET, &uri, None, Vec::new()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn config_rejects_control_characters_in_topic_and_organization() {
    let directory = tempdir().unwrap();
    let mut config = validation_config(&directory);
    config.topic.push('\n');
    assert!(config.validate().is_err());

    let mut config = validation_config(&directory);
    config.organization.push('\0');
    assert!(config.validate().is_err());
}
