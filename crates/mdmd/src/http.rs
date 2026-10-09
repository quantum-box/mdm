use crate::{
    config::Config,
    identity::Identity,
    storage::{self, IssuedCertificate, Store, StoreError},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use mdm_protocol::{CheckIn, CommandPayload, EnrollmentProfile};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct App {
    pub config: Config,
    pub store: Store,
    pub identity: Arc<Identity>,
}

/// Derived from the built-in TLS connection, never from an HTTP header.
/// `None` marks an anonymous TLS connection and suppresses proxy headers.
#[derive(Clone)]
pub struct AuthenticatedTlsPeer(pub Option<String>, pub i64);

struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        match error.downcast_ref::<StoreError>() {
            Some(StoreError::NotFound) => Self(StatusCode::NOT_FOUND, "not_found"),
            Some(StoreError::Unauthorized) => Self(StatusCode::UNAUTHORIZED, "unauthorized"),
            Some(StoreError::Conflict) => Self(StatusCode::CONFLICT, "state_conflict"),
            Some(StoreError::InvalidInput) => Self(StatusCode::BAD_REQUEST, "invalid_request"),
            None => {
                // OpenSSL, SQLite and HTTP errors may contain paths or confidential input.
                tracing::error!(category = "internal_request_error");
                Self(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }
}
mod operations;

type ApiResult<T> = Result<T, ApiError>;

// Bound expensive untrusted certificate work independently of body-size limits.
static SCEP_SLOTS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(4)));

pub fn router(app: App) -> Router {
    operations::routes(
        Router::new()
            .route(
                "/health",
                get(|| async {
                    Json(serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
                }),
            )
            .route("/scep", get(scep_get).post(scep_post))
            .route("/checkin", put(checkin))
            .route("/mdm", put(mdm))
            .route("/v1/enrollments", get(enrollments).post(enroll))
            .route("/v1/enrollments/{id}/revoke", post(revoke))
            .route(
                "/v1/enrollments/{id}/commands",
                post(enqueue).get(operations::command_list),
            )
            .route("/v1/commands/{id}", get(command))
            .route("/v1/commands/{id}/cancel", post(cancel))
            .route("/v1/audit", get(audits))
            .route("/v1/certificates", get(certificates))
            .route("/v1/enrollments/{id}/ddm/enable", post(enable_ddm))
            .route("/v1/enrollments/{id}/ddm/status", get(ddm_status))
            .route("/v1/declarations", get(declarations).post(put_declaration))
            .route(
                "/v1/declarations/{id}",
                axum::routing::delete(delete_declaration),
            )
            .route("/v1/declarations/{id}/targets", put(declaration_targets)),
    )
    .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
    .layer(middleware::from_fn(no_store))
    .with_state(app)
}
async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}
fn token_equal(actual: &str, expected: &str) -> bool {
    Sha256::digest(actual.as_bytes())
        .ct_eq(&Sha256::digest(expected.as_bytes()))
        .into()
}
fn authorize(app: &App, headers: &HeaderMap, write: bool) -> ApiResult<()> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if token_equal(token, &app.config.admin_token) {
        return Ok(());
    }
    if let Some(read) = &app.config.read_token
        && token_equal(token, read)
    {
        return if write {
            Err(ApiError(StatusCode::FORBIDDEN, "read_only"))
        } else {
            Ok(())
        };
    }
    Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
}
fn device_identity(
    app: &App,
    headers: &HeaderMap,
    peer: Option<Extension<AuthenticatedTlsPeer>>,
) -> ApiResult<String> {
    if let Some(Extension(peer)) = peer {
        if peer.0.is_some() && peer.1 <= storage::now() {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "expired_client_certificate",
            ));
        }
        return peer.0.ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "client_certificate_required",
        ));
    }
    if !app.config.trust_proxy {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "trusted_tls_proxy_required",
        ));
    }
    if headers
        .get("x-mdm-client-verify")
        .and_then(|v| v.to_str().ok())
        != Some("SUCCESS")
    {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "client_certificate_required",
        ));
    }
    let encoded = headers
        .get("x-mdm-client-cert")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "client_certificate_required",
        ))?;
    if encoded.len() > 32768 {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid_client_certificate",
        ));
    }
    let pem = percent_encoding::percent_decode_str(encoded).collect::<Vec<_>>();
    app.identity
        .verify_client_certificate(&pem)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_client_certificate"))
}
fn plist_response(bytes: Vec<u8>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        bytes,
    )
        .into_response()
}

async fn checkin(
    State(app): State<App>,
    headers: HeaderMap,
    peer: Option<Extension<AuthenticatedTlsPeer>>,
    body: Bytes,
) -> ApiResult<Response> {
    let fingerprint = device_identity(&app, &headers, peer)?;
    let message = mdm_protocol::parse_checkin(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_checkin"))?;
    match &message {
        CheckIn::Authenticate { topic, .. } | CheckIn::TokenUpdate { topic, .. }
            if topic != &app.config.topic =>
        {
            return Err(ApiError(StatusCode::BAD_REQUEST, "topic_mismatch"));
        }
        _ => {}
    }
    if let CheckIn::DeclarativeManagement {
        udid,
        endpoint,
        data,
    } = &message
    {
        let response = app.store.ddm_request(
            &fingerprint,
            udid,
            &endpoint.as_str(),
            data.as_ref(),
            storage::now(),
        )?;
        return Ok(match response {
            Some(value) => Json(value).into_response(),
            None => StatusCode::OK.into_response(),
        });
    }
    app.store.checkin(&fingerprint, &message, storage::now())?;
    Ok(plist_response(Vec::new()))
}
async fn mdm(
    State(app): State<App>,
    headers: HeaderMap,
    peer: Option<Extension<AuthenticatedTlsPeer>>,
    body: Bytes,
) -> ApiResult<Response> {
    let fingerprint = device_identity(&app, &headers, peer)?;
    let response = mdm_protocol::parse_response(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_response"))?;
    let command = app.store.poll(&fingerprint, &response, storage::now())?;
    Ok(plist_response(command.unwrap_or_default()))
}

#[derive(Deserialize)]
struct ScepQuery {
    operation: String,
    message: Option<String>,
}
async fn scep_get(State(app): State<App>, Query(query): Query<ScepQuery>) -> ApiResult<Response> {
    match query.operation.as_str() {
        "GetCACert" => Ok((
            [(header::CONTENT_TYPE, "application/x-x509-ca-cert")],
            app.identity.ca_der().map_err(ApiError::from)?,
        )
            .into_response()),
        "GetCACaps" => Ok((
            [(header::CONTENT_TYPE, "text/plain")],
            "POSTPKIOperation\nSHA-256\nAES\n",
        )
            .into_response()),
        "PKIOperation" => {
            let encoded = query
                .message
                .ok_or(ApiError(StatusCode::BAD_REQUEST, "missing_scep_message"))?;
            // Large SCEP requests use POSTPKIOperation; keep GET requests
            // within a bounded HTTP request line as well as a bounded body.
            if encoded.len() > 16 * 1024 {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "scep_message_too_large",
                ));
            }
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_scep_message"))?;
            bounded_scep_issue(app, bytes).await
        }
        _ => Err(ApiError(
            StatusCode::BAD_REQUEST,
            "unsupported_scep_operation",
        )),
    }
}
async fn scep_post(
    State(app): State<App>,
    Query(query): Query<ScepQuery>,
    body: Bytes,
) -> ApiResult<Response> {
    if query.operation != "PKIOperation" {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "unsupported_scep_operation",
        ));
    }
    bounded_scep_issue(app, body.to_vec()).await
}
async fn bounded_scep_issue(app: App, body: Vec<u8>) -> ApiResult<Response> {
    if body.len() > 1024 * 1024 {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "scep_message_too_large",
        ));
    }
    let permit = SCEP_SLOTS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "scep_busy"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        scep_issue(&app, &body)
    })
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?
}
fn scep_issue(app: &App, body: &[u8]) -> ApiResult<Response> {
    if body.len() > 1024 * 1024 {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "scep_message_too_large",
        ));
    }
    let request = app
        .identity
        .parse_request(body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_scep_request"))?;
    let response = app.store.issue_identity(
        &request.challenge,
        &storage::digest(body),
        storage::now(),
        |id| {
            let issued = app.identity.issue_response(&request, id)?;
            Ok(IssuedCertificate {
                fingerprint: issued.fingerprint,
                expires_at: issued.expires_at,
                response: issued.response,
            })
        },
    )?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-pki-message")],
        response,
    )
        .into_response())
}

async fn enroll(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, true)?;
    let challenge = hex::encode(rand::random::<[u8; 32]>());
    let id = app.store.create_enrollment(&challenge, storage::now())?;
    let profile = mdm_protocol::enrollment_profile(&EnrollmentProfile {
        public_url: app.config.public_url.trim_end_matches('/').to_owned(),
        topic: app.config.topic.clone(),
        challenge,
        enrollment_id: id.clone(),
        ca_certificate: app.identity.ca_der()?,
        organization: app.config.organization.clone(),
    })
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profile_generation_failed",
        )
    })?;
    let profile = String::from_utf8(profile).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "profile_generation_failed",
        )
    })?;
    Ok(Json(
        serde_json::json!({"id":id,"profile":profile,"challenge_expires_in_seconds":900}),
    ))
}
#[derive(Default, Deserialize)]
struct ListQuery {
    after: Option<String>,
}
async fn enrollments(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, false)?;
    let records = app.store.enrollments(query.after.as_deref())?;
    let after = if records.len() == 100 {
        records.last().map(|r| r.id.clone())
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({"enrollments":records,"next_cursor":after}),
    ))
}
async fn revoke(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    authorize(&app, &headers, true)?;
    app.store.revoke(&id, storage::now())?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnqueueRequest {
    idempotency_key: String,
    command: CommandPayload,
}
async fn enqueue(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<EnqueueRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, true)?;
    let id = app.store.enqueue(
        &id,
        &request.command,
        &request.idempotency_key,
        storage::now(),
    )?;
    Ok(Json(serde_json::json!({"id":id})))
}
async fn command(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<crate::storage::CommandView>> {
    authorize(&app, &headers, false)?;
    Ok(Json(app.store.command(&id)?))
}
async fn cancel(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    authorize(&app, &headers, true)?;
    app.store.cancel_command(&id, storage::now())?;
    Ok(StatusCode::NO_CONTENT)
}
async fn audits(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, false)?;
    let after = query
        .after
        .as_deref()
        .unwrap_or("0")
        .parse::<i64>()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_cursor"))?;
    let rows = app.store.audits(after)?;
    let next = if rows.len() == 100 {
        rows.last().and_then(|r| r["id"].as_i64())
    } else {
        None
    };
    Ok(Json(serde_json::json!({"audit":rows,"next_cursor":next})))
}
async fn certificates(
    State(app): State<App>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, false)?;
    let apns = match &app.config.apns_identity {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "certificate_read_failed")
            })?;
            let cert = openssl::x509::X509::from_pem(&pem).map_err(|_| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "certificate_read_failed")
            })?;
            serde_json::json!({"configured":true,"expires_at":cert.not_after().to_string(),"topic":app.config.topic})
        }
        None => serde_json::json!({"configured":false}),
    };
    Ok(Json(
        serde_json::json!({"ca":{"fingerprint":app.identity.ca_fingerprint()?,"expires_at":app.identity.certificate_expiry()?},"apns":apns}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableDdmRequest {
    idempotency_key: String,
}
async fn enable_ddm(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<EnableDdmRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, true)?;
    let command_id = app
        .store
        .enable_ddm(&id, &request.idempotency_key, storage::now())?;
    Ok(Json(
        serde_json::json!({"id":command_id,"enrollment_id":id}),
    ))
}
async fn declarations(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, false)?;
    let rows = app.store.declarations(query.after.as_deref())?;
    let next = if rows.len() == 100 {
        rows.last().map(|r| r.declaration.identifier.clone())
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({"declarations":rows,"next_cursor":next}),
    ))
}
async fn put_declaration(
    State(app): State<App>,
    headers: HeaderMap,
    Json(declaration): Json<mdm_core::AppleDeclaration>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, true)?;
    app.store.put_declaration(&declaration, storage::now())?;
    Ok(Json(
        serde_json::json!({"identifier":declaration.identifier,"server_token":declaration.server_token}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclarationTargetsRequest {
    enrollment_ids: Vec<String>,
}
async fn declaration_targets(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<DeclarationTargetsRequest>,
) -> ApiResult<StatusCode> {
    authorize(&app, &headers, true)?;
    app.store
        .replace_declaration_targets(&id, &request.enrollment_ids, storage::now())?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteDeclarationQuery {
    server_token: String,
}
async fn delete_declaration(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<DeleteDeclarationQuery>,
) -> ApiResult<StatusCode> {
    authorize(&app, &headers, true)?;
    app.store
        .delete_declaration(&id, &query.server_token, storage::now())?;
    Ok(StatusCode::NO_CONTENT)
}
async fn ddm_status(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authorize(&app, &headers, false)?;
    let after = query
        .after
        .as_deref()
        .unwrap_or("0")
        .parse::<i64>()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_cursor"))?;
    let rows = app.store.ddm_reports(&id, after)?;
    let next = if rows.len() == 100 {
        rows.last().and_then(|r| r["id"].as_i64())
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({"reports":rows,"next_cursor":next,"ordering":"server_receipt","enrollment_id":id}),
    ))
}
