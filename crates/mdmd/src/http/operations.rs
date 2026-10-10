use super::*;
use crate::apple::{AdeClient, VppAsset, VppClient};
use serde_json::{Value, json};
use std::path::PathBuf;
static APPLE_SLOTS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(4)));
fn apple_permit() -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
    APPLE_SLOTS
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "apple_requests_busy"))
}

pub(super) fn routes(router: Router<App>) -> Router<App> {
    router
        .route("/admin", get(admin))
        .route("/admin.js", get(admin_js))
        .route("/admin.css", get(admin_css))
        .route("/v1/enrollments/{id}/observations", get(observations))
        .route("/v1/enrollments/{id}/kiosk", post(kiosk))
        .route("/v1/enrollments/{id}/kiosk/release", post(release_kiosk))
        .route("/v1/enrollments/{id}/erase-intents", post(prepare_erase))
        .route("/v1/enrollments/{id}/erase", post(erase))
        .route("/v1/integrations/apple", get(integrations))
        .route("/v1/ade/devices", get(ade_devices))
        .route("/v1/ade/sync", post(ade_sync))
        .route("/v1/ade/profiles", post(ade_profile))
        .route("/v1/ade/assign", post(ade_assign))
        .route("/v1/ade/unassign", post(ade_unassign))
        .route("/v1/ade/devices/{serial}/reset", post(reset_bootstrap))
        .route("/ade/enroll", get(ade_enroll).post(ade_enroll))
        .route("/v1/apps/licenses", post(license))
        .route("/v1/apps/licenses/{adam_id}", get(license_status))
}
async fn admin() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../admin/index.html"),
    )
}
async fn admin_js() -> Response {
    static_response(
        "application/javascript; charset=utf-8",
        include_str!("../admin/admin.js"),
    )
}
async fn admin_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../admin/admin.css"),
    )
}
fn static_response(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE,content_type),(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")],body).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KioskRequest {
    bundle_id: String,
    idempotency_key: String,
}
async fn kiosk(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<KioskRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    Ok(Json(
        json!({"id":app.store.apply_kiosk(&id,&req.bundle_id,&req.idempotency_key,storage::now())?}),
    ))
}
async fn release_kiosk(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EnableDdmRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    Ok(Json(
        json!({"id":app.store.release_kiosk(&id,&req.idempotency_key,storage::now())?}),
    ))
}
async fn observations(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, false)?;
    Ok(Json(json!({"observations":app.store.observations(&id)?})))
}
async fn prepare_erase(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<storage::EraseIntent>> {
    authorize(&app, &headers, true)?;
    Ok(Json(app.store.prepare_erase(&id, storage::now())?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseRequest {
    intent_id: String,
    token: String,
    confirm_serial: String,
    idempotency_key: String,
}
async fn erase(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EraseRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    Ok(Json(
        json!({"id":app.store.confirm_erase(&id,&req.intent_id,&req.token,&req.confirm_serial,&req.idempotency_key,storage::now())?}),
    ))
}
fn configured_file(name: &str) -> ApiResult<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "apple_integration_not_configured",
    ))
}
fn ade_client() -> ApiResult<AdeClient> {
    let token = configured_file("MDM_ADE_TOKEN_FILE")?;
    let cert = std::env::var_os("MDM_ADE_PROVIDER_CERT_FILE").map(PathBuf::from);
    let key = std::env::var_os("MDM_ADE_PROVIDER_KEY_FILE").map(PathBuf::from);
    let client = match (cert, key) {
        (None, None) => AdeClient::from_token_file(&token),
        (Some(cert), Some(key)) => AdeClient::from_encrypted_token(&token, &cert, &key),
        _ => {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "ade_credentials_invalid",
            ));
        }
    };
    client.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "ade_credentials_invalid"))
}
fn vpp_client() -> ApiResult<VppClient> {
    VppClient::from_token_file(&configured_file("MDM_VPP_TOKEN_FILE")?).map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "apps_books_credentials_invalid",
        )
    })
}
fn apple_error(_: anyhow::Error) -> ApiError {
    ApiError(
        StatusCode::BAD_GATEWAY,
        "apple_request_failed_outcome_unknown",
    )
}
async fn integrations(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, false)?;
    Ok(Json(
        json!({"ade_configured":std::env::var_os("MDM_ADE_TOKEN_FILE").is_some(),"ade_device_trust_configured":std::env::var_os("MDM_ADE_DEVICE_CA_FILE").is_some(),"apps_books_configured":std::env::var_os("MDM_VPP_TOKEN_FILE").is_some(),"apns_configured":app.config.apns_identity.is_some(),"device_acceptance":"unverified"}),
    ))
}
async fn ade_devices(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, false)?;
    Ok(Json(json!({"devices":app.store.ade_devices()?})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncRequest {
    cursor: Option<String>,
}
async fn ade_sync(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    let _permit = apple_permit()?;
    let client = ade_client()?;
    let page = match req.cursor {
        Some(cursor) => client.sync_devices(&cursor, Some(1000)).await,
        None => client.fetch_devices(None, Some(1000)).await,
    }
    .map_err(apple_error)?;
    app.store.save_ade_devices(&page.devices, storage::now())?;
    Ok(Json(
        serde_json::to_value(page).map_err(anyhow::Error::from)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRequest {
    profile: Value,
    idempotency_key: String,
}
async fn ade_profile(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<ProfileRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    let _permit = apple_permit()?;
    let client = ade_client()?;
    let mut profile = req.profile;
    if !profile.is_object() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_profile"));
    }
    let profile_name = profile["profile_name"]
        .as_str()
        .filter(|name| !name.is_empty() && name.len() <= 255 && !name.chars().any(char::is_control))
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "invalid_profile"))?;
    let _ = profile_name;
    if let Some(anchors) = profile.get("anchor_certs") {
        let anchors = anchors
            .as_array()
            .filter(|a| a.len() <= 16)
            .ok_or(ApiError(
                StatusCode::BAD_REQUEST,
                "invalid_https_anchor_certs",
            ))?;
        for anchor in anchors {
            let text = anchor
                .as_str()
                .filter(|s| s.len() <= 180000)
                .ok_or(ApiError(
                    StatusCode::BAD_REQUEST,
                    "invalid_https_anchor_certs",
                ))?;
            let der = STANDARD
                .decode(text)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_https_anchor_certs"))?;
            openssl::x509::X509::from_der(&der)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_https_anchor_certs"))?;
        }
    }
    // This server implements direct enrollment. Interactive web enrollment is separate.
    profile
        .as_object_mut()
        .unwrap()
        .remove("configuration_web_url");
    profile["url"] = json!(format!(
        "{}/ade/enroll",
        app.config
            .bootstrap_url
            .as_deref()
            .unwrap_or(&app.config.public_url)
            .trim_end_matches('/')
    ));

    profile["is_supervised"] = json!(true);
    profile["await_device_configured"] = json!(true);
    profile["is_mandatory"] = json!(true);
    profile["is_mdm_removable"] = json!(false);
    if let Some(prior) = app.store.reserve_apple_request(
        &req.idempotency_key,
        "ade_profile",
        &profile,
        storage::now(),
    )? {
        return prior_result(prior);
    }
    let result = serde_json::to_value(client.define_profile(&profile).await.map_err(apple_error)?)
        .map_err(anyhow::Error::from)?;
    let uuid = result["profile_uuid"]
        .as_str()
        .ok_or(ApiError(StatusCode::BAD_GATEWAY, "apple_response_invalid"))?;
    app.store.save_ade_profile(uuid, &profile)?;
    app.store
        .finish_apple_request(&req.idempotency_key, &result, storage::now())?;
    Ok(Json(result))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignRequest {
    profile_uuid: String,
    devices: Vec<String>,
    idempotency_key: String,
}
async fn ade_assign(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<AssignRequest>,
) -> ApiResult<Json<Value>> {
    ade_assignment(app, headers, req, false).await
}
async fn ade_unassign(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<AssignRequest>,
) -> ApiResult<Json<Value>> {
    ade_assignment(app, headers, req, true).await
}
async fn ade_assignment(
    app: App,
    headers: HeaderMap,
    req: AssignRequest,
    unassign: bool,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    let _permit = apple_permit()?;
    let client = ade_client()?;
    if req.devices.is_empty()
        || req.devices.len() > 1000
        || req
            .devices
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        || req.profile_uuid.is_empty()
        || req.profile_uuid.len() > 512
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_assignment"));
    }
    let body = json!({"profile_uuid":req.profile_uuid,"devices":req.devices});
    if let Some(prior) = app.store.reserve_apple_request(
        &req.idempotency_key,
        if unassign {
            "ade_unassign"
        } else {
            "ade_assign"
        },
        &body,
        storage::now(),
    )? {
        return prior_result(prior);
    }
    let response = if unassign {
        client
            .unassign_profile(&req.profile_uuid, &req.devices)
            .await
    } else {
        client.assign_profile(&req.profile_uuid, &req.devices).await
    }
    .map_err(apple_error)?;
    let result = serde_json::to_value(response).map_err(anyhow::Error::from)?;
    app.store
        .finish_apple_request(&req.idempotency_key, &result, storage::now())?;
    Ok(Json(result))
}
fn prior_result(prior: storage::AppleRequest) -> ApiResult<Json<Value>> {
    if prior.state != "completed" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "apple_request_outcome_unknown",
        ));
    }
    Ok(Json(prior.result.unwrap_or(Value::Null)))
}
async fn reset_bootstrap(
    State(app): State<App>,
    headers: HeaderMap,
    Path(serial): Path<String>,
) -> ApiResult<StatusCode> {
    authorize(&app, &headers, true)?;
    app.store.reset_ade_bootstrap(&serial, storage::now())?;
    Ok(StatusCode::NO_CONTENT)
}
async fn ade_enroll(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let anchors_path = configured_file("MDM_ADE_DEVICE_CA_FILE")?;
    let metadata = std::fs::symlink_metadata(&anchors_path)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "ade_device_trust_invalid"))?;
    if !metadata.file_type().is_file() || metadata.len() > 256 * 1024 {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "ade_device_trust_invalid",
        ));
    }
    let anchors = std::fs::read(anchors_path)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "ade_device_trust_invalid"))?;
    let (machine, hash) = if body.is_empty() {
        let header = headers
            .get("x-apple-aspen-deviceinfo")
            .and_then(|h| h.to_str().ok())
            .ok_or(ApiError(
                StatusCode::UNAUTHORIZED,
                "signed_ade_identity_required",
            ))?;
        (
            crate::apple::verify_ade_machine_info(header, &anchors),
            storage::digest(header.as_bytes()),
        )
    } else {
        (
            crate::apple::verify_ade_machine_info_der(&body, &anchors),
            storage::digest(&body),
        )
    };
    let machine =
        machine.map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_signed_ade_identity"))?;
    let profile = app.store.ade_bootstrap(
        &machine.serial,
        machine.udid.as_deref().ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid_signed_ade_identity",
        ))?,
        &hash,
        storage::now(),
        |id, challenge| {
            Ok(mdm_protocol::enrollment_profile_with_bootstrap(
                &EnrollmentProfile {
                    public_url: app.config.public_url.trim_end_matches('/').to_owned(),
                    topic: app.config.topic.clone(),
                    challenge: challenge.into(),
                    enrollment_id: id.into(),
                    ca_certificate: app.identity.ca_der()?,
                    organization: app.config.organization.clone(),
                },
                app.config.bootstrap_url.as_deref(),
            )?)
        },
    )?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-apple-aspen-config")],
        profile,
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LicenseRequest {
    adam_id: u64,
    serial_number: String,
    assign: bool,
    idempotency_key: String,
}
async fn license(
    State(app): State<App>,
    headers: HeaderMap,
    Json(req): Json<LicenseRequest>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, true)?;
    let _permit = apple_permit()?;
    let client = vpp_client()?;
    if req.adam_id == 0
        || req.serial_number.is_empty()
        || req.serial_number.len() > 128
        || req.serial_number.chars().any(char::is_control)
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_license_request"));
    }
    let asset = VppAsset::new(req.adam_id.to_string(), None)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_license_request"))?;
    let body = json!({"adam_id":req.adam_id,"serial_number":req.serial_number,"assign":req.assign});
    if let Some(prior) = app.store.reserve_apple_request(
        &req.idempotency_key,
        "apps_books_license",
        &body,
        storage::now(),
    )? {
        return prior_result(prior);
    }
    let serials = [req.serial_number.clone()];
    let assets = [asset];
    let event = if req.assign {
        client.associate(&assets, &serials).await
    } else {
        client.disassociate(&assets, &serials).await
    }
    .map_err(apple_error)?;
    let result =
        json!({"event_id":event.event_id,"requested_assignment":req.assign,"state":"processing"});
    app.store
        .save_license_event(req.adam_id, &req.serial_number, &result, storage::now())?;
    app.store
        .finish_apple_request(&req.idempotency_key, &result, storage::now())?;
    Ok(Json(result))
}
#[derive(Deserialize)]
struct LicenseQuery {
    serial: String,
}
async fn license_status(
    State(app): State<App>,
    headers: HeaderMap,
    Path(adam_id): Path<u64>,
    Query(req): Query<LicenseQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, false)?;
    if adam_id == 0
        || req.serial.is_empty()
        || req.serial.len() > 128
        || req.serial.chars().any(char::is_control)
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_license_request"));
    }
    let _permit = apple_permit()?;
    let client = vpp_client()?;
    let assignment = client
        .assignment(&adam_id.to_string(), &req.serial)
        .await
        .map_err(apple_error)?;
    let event = match app.store.license_event(adam_id, &req.serial) {
        Ok(event) => Some(event),
        Err(error)
            if matches!(
                error.downcast_ref::<StoreError>(),
                Some(StoreError::NotFound)
            ) =>
        {
            None
        }
        Err(error) => return Err(error.into()),
    };
    let status = if let Some(event_id) = event.as_ref().and_then(|e| e["event_id"].as_str()) {
        Some(client.status(event_id).await.map_err(apple_error)?)
    } else {
        None
    };
    Ok(Json(
        json!({"request":event,"apple_assignment":assignment,"apple_status":status,"observed_at":storage::now()}),
    ))
}

pub(super) async fn command_list(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&app, &headers, false)?;
    let commands = app.store.commands(&id, query.after.as_deref())?;
    let next = if commands.len() == 100 {
        commands.last().map(|c| c.id.clone())
    } else {
        None
    };
    Ok(Json(json!({"commands":commands,"next_cursor":next})))
}
