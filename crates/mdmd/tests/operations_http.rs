use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mdm_protocol::CheckIn;
use mdmd::{
    config::Config,
    http::{App, router},
    identity::Identity,
    storage::{self, IssuedCertificate, Store},
};
use std::{net::SocketAddr, sync::Arc};
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

fn request(method: Method, uri: &str, token: Option<&str>, body: Vec<u8>) -> Request<Body> {
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
    let mut request = request(method, uri, token, serde_json::to_vec(value).unwrap());
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    request
}

async fn send(app: &Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.unwrap()
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(response).await).unwrap()
}

fn active_enrollment(app: &TestApp) -> String {
    let challenge = "operations-http-challenge";
    let id = app
        .store
        .create_enrollment(challenge, storage::now())
        .unwrap();
    let fingerprint = format!("operations-http-fingerprint-{id}");
    app.store
        .issue_identity(
            challenge,
            "operations-http-request",
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
    app.store
        .checkin(
            &fingerprint,
            &CheckIn::Authenticate {
                udid: "operations-http-udid".into(),
                topic: "com.apple.mgmt.test".into(),
                serial_number: Some("OPERATIONS-HTTP".into()),
                os_version: Some("18.0".into()),
            },
            storage::now(),
        )
        .unwrap();
    app.store
        .checkin(
            &fingerprint,
            &CheckIn::TokenUpdate {
                udid: "operations-http-udid".into(),
                topic: "com.apple.mgmt.test".into(),
                token: vec![1, 2, 3, 4],
                push_magic: "operations-http-push".into(),
                unlock_token: None,
                awaiting_configuration: false,
            },
            storage::now(),
        )
        .unwrap();
    id
}

#[tokio::test]
async fn admin_assets_are_public_same_origin_and_have_csp() {
    let app = test_app();
    for (path, content_type) in [
        ("/admin", "text/html"),
        ("/admin.js", "application/javascript"),
        ("/admin.css", "text/css"),
    ] {
        let response = send(&app.router, request(Method::GET, path, None, Vec::new())).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with(content_type))
        );
        let csp = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("style-src 'self'"));
        assert!(csp.contains("connect-src 'self'"));
        let body = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(!body.contains(ADMIN_TOKEN));
        assert!(!body.contains(READ_TOKEN));
        if path == "/admin.js" {
            assert!(!body.contains("localStorage"));
            assert!(!body.contains("sessionStorage"));
        }
    }
}

#[tokio::test]
async fn read_token_cannot_mutate_operations() {
    let app = test_app();
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            "/v1/enrollments/missing/kiosk",
            Some(READ_TOKEN),
            &serde_json::json!({
                "bundle_id": "com.example.kiosk",
                "idempotency_key": "read-only-kiosk"
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn erase_rejects_invalid_idempotency_request_as_bad_request() {
    let app = test_app();
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            "/v1/enrollments/missing/erase",
            Some(ADMIN_TOKEN),
            &serde_json::json!({
                "intent_id": "intent",
                "token": "token",
                "confirm_serial": "serial",
                "idempotency_key": ""
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn legacy_global_observations_route_is_not_exposed() {
    let app = test_app();
    let response = send(
        &app.router,
        request(
            Method::GET,
            "/v1/observations?after=0",
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let enrollment_id = app
        .store
        .create_enrollment("observations-http-challenge", storage::now())
        .unwrap();
    let response = send(
        &app.router,
        request(
            Method::GET,
            &format!("/v1/enrollments/{enrollment_id}/observations"),
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert!(value["observations"].is_array());
}

#[tokio::test]
async fn apple_integration_health_reports_configuration_without_calling_apple() {
    let app = test_app();
    let response = send(
        &app.router,
        request(
            Method::GET,
            "/v1/integrations/apple",
            Some(READ_TOKEN),
            Vec::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert!(value["ade_configured"].is_boolean());
    assert!(value["ade_device_trust_configured"].is_boolean());
    assert!(value["apps_books_configured"].is_boolean());
    assert!(value["apns_configured"].is_boolean());
    assert_eq!(value["device_acceptance"], "unverified");
}

#[tokio::test]
async fn kiosk_rejects_active_device_without_supervision_observation() {
    let app = test_app();
    let enrollment_id = active_enrollment(&app);
    let response = send(
        &app.router,
        json_request(
            Method::POST,
            &format!("/v1/enrollments/{enrollment_id}/kiosk"),
            Some(ADMIN_TOKEN),
            &serde_json::json!({
                "bundle_id": "com.example.kiosk",
                "idempotency_key": "kiosk-no-supervision"
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
