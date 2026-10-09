//! Apple Automated Device Enrollment and Apps & Books adapters.
//!
//! The adapters in this module deliberately keep Apple credentials at the
//! edge of the process.  They never log server-token material and they expose
//! JSON values from Apple only as data; they do not turn a response into a
//! local install or proxy an application manifest.  Callers that want to
//! install an app must send an HTTPS manifest URL to the device through an MDM
//! command.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use openssl::{
    cms::CmsContentInfo,
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
    x509::{X509, store::X509StoreBuilder},
};
use reqwest::{Client, Method, StatusCode, Url, header::AUTHORIZATION, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// Apple's Automated Device Enrollment web service.
pub const ADE_BASE_URL: &str = "https://mdmenrollment.apple.com";
/// Apple's Apps & Books (VPP) v2 web service.
pub const VPP_BASE_URL: &str = "https://vpp.itunes.apple.com/mdm/v2";
/// Device-management protocol version used for profile assignment.
pub const ADE_PROTOCOL_VERSION: &str = "10";
const MAX_TOKEN_FILE: usize = 2 * 1024 * 1024;
const MAX_DECRYPTED_TOKEN: usize = 64 * 1024;
const MAX_HEADER_BLOB: usize = 64 * 1024;
const MAX_JSON_BODY: usize = 2 * 1024 * 1024;
const MAX_TRUST_ANCHOR_FILE: usize = 256 * 1024;
const MAX_SERIALS: usize = 1_000;
const MAX_ASSETS: usize = 100;
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// A device record returned by Apple's ADE service.
///
/// Apple adds fields to this object over time, so the adapter keeps unknown
/// fields in a JSON value instead of inventing a lossy local schema.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdeDevicePage {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub devices: Vec<Value>,
    #[serde(default)]
    pub fetched_until: Option<String>,
    #[serde(default)]
    pub more_to_follow: bool,
}

/// A response to an ADE profile definition operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdeProfileResponse {
    #[serde(flatten)]
    pub value: Map<String, Value>,
}

/// A profile assignment result returned by Apple.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdeProfileAssignment {
    #[serde(flatten)]
    pub value: Map<String, Value>,
}

/// The four values in an Apple School Manager or Apple Business server token.
///
/// This type intentionally has no public fields and no `Debug` implementation;
/// callers should pass the token to [`AdeClient::from_encrypted_token`] or
/// [`AdeClient::from_token_file`].
pub struct AdeServerToken {
    consumer_key: String,
    consumer_secret: String,
    access_token: String,
    access_secret: String,
}

/// Authenticated Automated Device Enrollment client.
pub struct AdeClient {
    client: Client,
    token: Arc<AdeServerToken>,
    session: Arc<Mutex<Option<String>>>,
    base_url: Url,
}

impl AdeClient {
    /// Decrypts an Apple `.p7m` server token with the provider RSA identity.
    ///
    /// The encrypted token is parsed as S/MIME, DER, or PEM CMS.  The token
    /// file and private key must be mode `0600` on Unix; the provider
    /// certificate is public and may be readable by the process user.
    pub fn from_encrypted_token(
        token_path: &Path,
        provider_cert_path: &Path,
        provider_key_path: &Path,
    ) -> Result<Self> {
        let token_bytes = read_private_file(token_path, MAX_TOKEN_FILE, "ADE server token")?;
        let key_bytes = read_private_file(
            provider_key_path,
            MAX_TOKEN_FILE,
            "ADE provider private key",
        )?;
        let cert_bytes = read_bounded_file(
            provider_cert_path,
            MAX_TOKEN_FILE,
            "ADE provider certificate",
        )?;
        let key =
            PKey::private_key_from_pem(&key_bytes).context("parse ADE provider RSA private key")?;
        if key.rsa().is_err() {
            bail!("ADE provider identity must use an RSA private key");
        }
        let cert = X509::from_pem(&cert_bytes).context("parse ADE provider certificate")?;
        let cert_key = cert
            .public_key()
            .context("read ADE provider certificate public key")?;
        if !cert_key.public_eq(&key) {
            bail!("ADE provider certificate and private key do not match");
        }
        let clear = decrypt_cms(&token_bytes, &key, &cert)?;
        if clear.len() > MAX_DECRYPTED_TOKEN {
            bail!("decrypted ADE server token is too large");
        }
        let token = Arc::new(parse_ade_server_token(&clear)?);
        build_ade_client(token, Url::parse(ADE_BASE_URL)?)
    }

    /// Loads a manually decrypted plain-text Apple server-token file.
    pub fn from_token_file(token_path: &Path) -> Result<Self> {
        let bytes = read_private_file(token_path, MAX_TOKEN_FILE, "ADE server token")?;
        let token = Arc::new(parse_ade_server_token(&bytes)?);
        build_ade_client(token, Url::parse(ADE_BASE_URL)?)
    }

    /// Constructs a client from already decrypted credentials.
    ///
    /// This is useful for a secret manager that keeps the token out of the
    /// filesystem.  The returned value never formats the credentials.
    pub fn from_credentials(
        consumer_key: impl Into<String>,
        consumer_secret: impl Into<String>,
        access_token: impl Into<String>,
        access_secret: impl Into<String>,
    ) -> Result<Self> {
        let token = Arc::new(validate_ade_token(AdeServerToken {
            consumer_key: consumer_key.into(),
            consumer_secret: consumer_secret.into(),
            access_token: access_token.into(),
            access_secret: access_secret.into(),
        })?);
        build_ade_client(token, Url::parse(ADE_BASE_URL)?)
    }

    /// Requests a fresh short-lived Apple authentication session.
    pub async fn authenticate(&self) -> Result<()> {
        let session = self.request_session().await?;
        let mut current = self.session.lock().await;
        *current = Some(session);
        Ok(())
    }

    /// Fetches a page of devices from Apple Business or Apple School Manager.
    pub async fn fetch_devices(
        &self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<AdeDevicePage> {
        let mut body = Map::new();
        if let Some(cursor) = cursor {
            insert_bounded_string(&mut body, "cursor", cursor, 4_096)?;
        }
        if let Some(limit) = limit {
            if !(1..=MAX_SERIALS as u32).contains(&limit) {
                bail!("ADE device page limit must be between 1 and 1000");
            }
            body.insert("limit".to_owned(), Value::from(limit));
        }
        let value = self
            .json_request(Method::POST, "/server/devices", Some(Value::Object(body)))
            .await?;
        parse_device_page(value)
    }

    /// Continues an ADE device synchronization cursor.
    pub async fn sync_devices(&self, cursor: &str, limit: Option<u32>) -> Result<AdeDevicePage> {
        if cursor.is_empty() || cursor.len() > 4_096 {
            bail!("ADE synchronization cursor is invalid");
        }
        let mut body = Map::new();
        body.insert("cursor".to_owned(), Value::String(cursor.to_owned()));
        if let Some(limit) = limit {
            if !(1..=MAX_SERIALS as u32).contains(&limit) {
                bail!("ADE device page limit must be between 1 and 1000");
            }
            body.insert("limit".to_owned(), Value::from(limit));
        }
        let value = self
            .json_request(Method::POST, "/devices/sync", Some(Value::Object(body)))
            .await?;
        parse_device_page(value)
    }

    /// Defines an ADE profile.
    ///
    /// The profile is passed through as JSON to retain Apple's evolving
    /// schema.  URLs in the profile are validated as HTTPS URLs, but this
    /// method never fetches them.
    pub async fn define_profile(&self, profile: &Value) -> Result<AdeProfileResponse> {
        validate_profile(profile)?;
        let value = self
            .json_request(Method::POST, "/profile", Some(profile.clone()))
            .await?;
        object_response(value, "ADE profile definition")
    }

    /// Gets one ADE profile by UUID.
    pub async fn get_profile(&self, profile_uuid: &str) -> Result<AdeProfileResponse> {
        validate_identifier(profile_uuid, "ADE profile UUID", 512)?;
        let mut url = self.endpoint("/profile")?;
        url.query_pairs_mut()
            .append_pair("profile_uuid", profile_uuid);
        let value = self.json_request_url(Method::GET, url, None).await?;
        object_response(value, "ADE profile")
    }

    /// Assigns an ADE profile to up to 1,000 serial numbers.
    pub async fn assign_profile(
        &self,
        profile_uuid: &str,
        serial_numbers: &[String],
    ) -> Result<AdeProfileAssignment> {
        self.profile_devices("/profile/devices", profile_uuid, serial_numbers, false)
            .await
    }

    /// Removes an ADE profile from up to 1,000 serial numbers.
    pub async fn unassign_profile(
        &self,
        profile_uuid: &str,
        serial_numbers: &[String],
    ) -> Result<AdeProfileAssignment> {
        self.profile_devices("/profile/devices", profile_uuid, serial_numbers, true)
            .await
    }

    async fn profile_devices(
        &self,
        path: &str,
        profile_uuid: &str,
        serial_numbers: &[String],
        remove: bool,
    ) -> Result<AdeProfileAssignment> {
        validate_identifier(profile_uuid, "ADE profile UUID", 512)?;
        validate_serials(serial_numbers)?;
        let body = json!({
            "devices": serial_numbers,
            "profile_uuid": profile_uuid,
        });
        let method = if remove { Method::DELETE } else { Method::POST };
        let value = self.json_request(method, path, Some(body)).await?;
        object_assignment(value)
    }

    async fn request_session(&self) -> Result<String> {
        let url = self.endpoint("/session")?;
        let (authorization, _) = oauth_authorization(&self.token, Method::GET, &url)?;
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .context("request ADE authentication session")?;
        let status = response.status();
        if !status.is_success() {
            discard_body(response);
            bail!(
                "ADE authentication session failed (HTTP {})",
                status.as_u16()
            );
        }
        let value = bounded_json(response).await?;
        let token = value
            .get("auth_session_token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ADE session response omitted auth_session_token"))?;
        validate_secret(token, "ADE authentication session")?;
        Ok(token.to_owned())
    }

    async fn json_request(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let url = self.endpoint(path)?;
        self.json_request_url(method, url, body).await
    }

    async fn json_request_url(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut retried = false;
        loop {
            let session = {
                let current = self.session.lock().await;
                current.clone()
            };
            let session = match session {
                Some(session) => session,
                None => {
                    let session = self.request_session().await?;
                    let mut current = self.session.lock().await;
                    if current.is_none() {
                        *current = Some(session.clone());
                    }
                    session
                }
            };
            let (authorization, _) = oauth_authorization(&self.token, method.clone(), &url)?;
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .header(AUTHORIZATION, authorization)
                .header("X-ADM-Auth-Session", session)
                .header("X-Server-Protocol-Version", ADE_PROTOCOL_VERSION);
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request.send().await.context("request ADE service")?;
            if response.status() == StatusCode::UNAUTHORIZED && !retried {
                discard_body(response);
                let session = self.request_session().await?;
                let mut current = self.session.lock().await;
                *current = Some(session);
                retried = true;
                continue;
            }
            let status = response.status();
            if !status.is_success() {
                discard_body(response);
                bail!("ADE service request failed (HTTP {})", status.as_u16());
            }
            let header_session = response
                .headers()
                .get("X-ADM-Auth-Session")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            if let Some(header_session) = header_session
                && validate_secret(&header_session, "ADE authentication session").is_ok()
            {
                let mut current = self.session.lock().await;
                *current = Some(header_session);
            }
            return bounded_json(response).await;
        }
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            bail!("invalid Apple endpoint path");
        }
        Ok(join_api_path(&self.base_url, path))
    }

    #[doc(hidden)]
    /// Creates a loopback-only client for protocol tests.  Production callers
    /// should use one of the credential-loading constructors above.
    pub fn for_test(
        base_url: &str,
        consumer_key: &str,
        consumer_secret: &str,
        access_token: &str,
        access_secret: &str,
    ) -> Result<Self> {
        let url = Url::parse(base_url).context("parse ADE test URL")?;
        if !is_loopback_host(&url) {
            bail!("test Apple endpoint must be loopback");
        }
        let token = validate_ade_token(AdeServerToken {
            consumer_key: consumer_key.to_owned(),
            consumer_secret: consumer_secret.to_owned(),
            access_token: access_token.to_owned(),
            access_secret: access_secret.to_owned(),
        })?;
        build_ade_client(Arc::new(token), url)
    }
}

/// A device-assignable Apps & Books asset.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VppAsset {
    #[serde(rename = "adamId")]
    pub adam_id: String,
    #[serde(rename = "pricingParam", skip_serializing_if = "Option::is_none")]
    pub pricing_param: Option<String>,
}

impl VppAsset {
    pub fn new(adam_id: impl Into<String>, pricing_param: Option<String>) -> Result<Self> {
        let asset = Self {
            adam_id: adam_id.into(),
            pricing_param,
        };
        validate_identifier(&asset.adam_id, "Apps & Books adamId", 128)?;
        if let Some(pricing_param) = &asset.pricing_param {
            validate_identifier(pricing_param, "Apps & Books pricingParam", 128)?;
        }
        Ok(asset)
    }
}

/// The asynchronous operation returned by Apps & Books asset association.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VppOperation {
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "tokenExpirationDate", default)]
    pub token_expiration_date: Option<String>,
    #[serde(rename = "uId", default)]
    pub uid: Option<String>,
}

/// Authenticated Apple Apps & Books (VPP) v2 client.
pub struct VppClient {
    client: Client,
    token: String,
    base_url: Url,
}

/// Validates Apple integration files configured through the process
/// environment without making a network request.
///
/// The optional variables are deliberately checked only when present so a
/// standalone server can start without ADE or Apps & Books credentials.  ADE
/// accepts either a clear token (`MDM_ADE_TOKEN_FILE`) or an encrypted `.p7m`
/// token together with `MDM_ADE_PROVIDER_CERT_FILE` and
/// `MDM_ADE_PROVIDER_KEY_FILE`.  A partial provider identity is rejected so a
/// deployment cannot accidentally treat an encrypted token as clear text.
/// `MDM_ADE_DEVICE_CA_FILE` is the public Apple Device CA trust-anchor bundle
/// used by the enrollment endpoint.
pub fn validate_configuration() -> Result<()> {
    let token_path = std::env::var_os("MDM_ADE_TOKEN_FILE").map(std::path::PathBuf::from);
    let provider_cert_path =
        std::env::var_os("MDM_ADE_PROVIDER_CERT_FILE").map(std::path::PathBuf::from);
    let provider_key_path =
        std::env::var_os("MDM_ADE_PROVIDER_KEY_FILE").map(std::path::PathBuf::from);
    match (
        token_path.as_deref(),
        provider_cert_path.as_deref(),
        provider_key_path.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(token), None, None) => {
            AdeClient::from_token_file(token).context("validate ADE token file")?;
        }
        (Some(token), Some(cert), Some(key)) => {
            AdeClient::from_encrypted_token(token, cert, key)
                .context("validate encrypted ADE token files")?;
        }
        _ => bail!(
            "MDM_ADE_TOKEN_FILE, MDM_ADE_PROVIDER_CERT_FILE, and MDM_ADE_PROVIDER_KEY_FILE must be configured together for an encrypted ADE token"
        ),
    }

    if let Some(path) = std::env::var_os("MDM_ADE_DEVICE_CA_FILE").map(std::path::PathBuf::from) {
        let bytes = read_bounded_file(&path, MAX_TRUST_ANCHOR_FILE, "ADE device trust anchors")?;
        let certs = X509::stack_from_pem(&bytes).context("parse ADE device trust anchors")?;
        if certs.is_empty() || certs.len() > 64 {
            bail!("ADE device trust anchors are empty or too numerous");
        }
    }

    if let Some(path) = std::env::var_os("MDM_VPP_TOKEN_FILE").map(std::path::PathBuf::from) {
        VppClient::from_token_file(&path).context("validate Apps & Books token file")?;
    }
    Ok(())
}

impl VppClient {
    /// Loads a plain location-based Apps & Books content token.
    pub fn from_token_file(token_path: &Path) -> Result<Self> {
        let bytes = read_private_file(token_path, MAX_TOKEN_FILE, "Apps & Books token")?;
        let token = parse_vpp_token(&bytes)?;
        Self::new(token)
    }

    /// Constructs a VPP client from a secret supplied by a secret manager.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        build_vpp_client(
            validate_secret_value(token.into(), "Apps & Books token")?,
            Url::parse(VPP_BASE_URL)?,
        )
    }

    /// Returns Apple service configuration and token metadata.
    pub async fn service_config(&self) -> Result<Value> {
        self.json_request(Method::GET, "/service/config", None)
            .await
    }

    /// Queries device-assignable assets.  This method does not download an
    /// application or its manifest.
    pub async fn assets(&self, query: &[(&str, &str)]) -> Result<Value> {
        let mut url = self.endpoint("/assets")?;
        {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                validate_identifier(name, "Apps & Books query name", 128)?;
                if value.len() > 2_048 || value.bytes().any(|byte| byte.is_ascii_control()) {
                    bail!("Apps & Books query value is invalid");
                }
                pairs.append_pair(name, value);
            }
        }
        self.json_request_url(Method::GET, url, None).await
    }

    /// Returns the current device assignment for one `adamId` and serial
    /// number.  This is Apple's v2 assignment inventory, not the deprecated
    /// license-ID endpoint.
    pub async fn assignment(&self, adam_id: &str, serial_number: &str) -> Result<Value> {
        validate_identifier(adam_id, "Apps & Books adamId", 128)?;
        validate_identifier(serial_number, "Apple serial number", 128)?;
        let mut url = self.endpoint("/assignments")?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("adamId", adam_id);
            pairs.append_pair("serialNumber", serial_number);
        }
        self.json_request_url(Method::GET, url, None).await
    }

    /// Alias for [`Self::assignment`] used by management layers that expose a
    /// license-status operation.
    pub async fn license_status(&self, adam_id: &str, serial_number: &str) -> Result<Value> {
        self.assignment(adam_id, serial_number).await
    }

    /// Associates device licenses with serial numbers.  Apple processes the
    /// operation asynchronously; callers must poll [`Self::status`].
    pub async fn associate(
        &self,
        assets: &[VppAsset],
        serial_numbers: &[String],
    ) -> Result<VppOperation> {
        self.associate_or_disassociate("/assets/associate", assets, serial_numbers)
            .await
    }

    /// Disassociates device licenses from serial numbers.
    pub async fn disassociate(
        &self,
        assets: &[VppAsset],
        serial_numbers: &[String],
    ) -> Result<VppOperation> {
        self.associate_or_disassociate("/assets/disassociate", assets, serial_numbers)
            .await
    }

    /// Returns the asynchronous status for an association event.
    pub async fn status(&self, event_id: &str) -> Result<Value> {
        validate_identifier(event_id, "Apps & Books eventId", 512)?;
        let mut url = self.endpoint("/status")?;
        url.query_pairs_mut().append_pair("eventId", event_id);
        self.json_request_url(Method::GET, url, None).await
    }

    #[doc(hidden)]
    /// Creates a loopback-only client for protocol tests.
    pub fn for_test(base_url: &str, token: impl Into<String>) -> Result<Self> {
        let url = Url::parse(base_url).context("parse Apps & Books test URL")?;
        if !is_loopback_host(&url) {
            bail!("test Apple endpoint must be loopback");
        }
        build_vpp_client(
            validate_secret_value(token.into(), "Apps & Books token")?,
            url,
        )
    }

    async fn associate_or_disassociate(
        &self,
        path: &str,
        assets: &[VppAsset],
        serial_numbers: &[String],
    ) -> Result<VppOperation> {
        if assets.is_empty() || assets.len() > MAX_ASSETS {
            bail!("Apps & Books asset count must be between 1 and 100");
        }
        validate_serials(serial_numbers)?;
        for asset in assets {
            validate_identifier(&asset.adam_id, "Apps & Books adamId", 128)?;
            if let Some(pricing_param) = &asset.pricing_param {
                validate_identifier(pricing_param, "Apps & Books pricingParam", 128)?;
            }
        }
        let body = json!({"assets": assets, "serialNumbers": serial_numbers});
        let value = self.json_request(Method::POST, path, Some(body)).await?;
        serde_json::from_value(value).context("parse Apps & Books operation response")
    }

    async fn json_request(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let url = self.endpoint(path)?;
        self.json_request_url(method, url, body).await
    }

    async fn json_request_url(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut request = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .context("request Apps & Books service")?;
        let status = response.status();
        if !status.is_success() {
            discard_body(response);
            bail!("Apps & Books request failed (HTTP {})", status.as_u16());
        }
        bounded_json(response).await
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            bail!("invalid Apps & Books endpoint path");
        }
        Ok(join_api_path(&self.base_url, path))
    }
}

/// Validates the URL a caller puts into an MDM installation manifest.
///
/// The adapter deliberately has no method that downloads this URL.  Apple
/// devices fetch it directly over HTTPS.
pub fn validate_manifest_url(manifest_url: &str) -> Result<Url> {
    let url = Url::parse(manifest_url).context("parse app manifest URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("app manifest URL must be HTTPS without credentials or fragments");
    }
    Ok(url)
}

/// Builds the minimal ADE profile body used by the direct enrollment flow.
///
/// `anchor_cert_der` is encoded exactly as Apple specifies for `AnchorCerts`.
/// The returned profile still belongs to the caller, which may add other
/// documented Apple profile fields before calling [`AdeClient::define_profile`].
pub fn build_ade_profile(
    profile_name: &str,
    enrollment_url: &str,
    anchor_cert_der: &[u8],
) -> Result<Value> {
    validate_identifier(profile_name, "ADE profile name", 255)?;
    validate_manifest_url(enrollment_url).context("ADE enrollment URL")?;
    if anchor_cert_der.is_empty() || anchor_cert_der.len() > 128 * 1024 {
        bail!("ADE profile anchor certificate is empty or too large");
    }
    X509::from_der(anchor_cert_der).context("parse ADE anchor certificate")?;
    Ok(json!({
        "profile_name": profile_name,
        "url": enrollment_url,
        "anchor_certs": [BASE64.encode(anchor_cert_der)],
        "await_device_configured": true,
        "is_supervised": true,
        "is_mandatory": true,
        "is_mdm_removable": false,
    }))
}

/// Machine attributes Apple sends as a CMS-signed ADE enrollment request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdeMachineInfo {
    pub serial: String,
    pub udid: Option<String>,
    pub product: Option<String>,
    /// The build version (`VERSION`) supplied by the device.
    pub version: Option<String>,
    pub os_version: Option<String>,
}

/// Parses the Base64 CMS envelope from `x-apple-aspen-deviceinfo`.
///
/// This verifies the CMS signature and extracts the signed plist, but it does
/// not assert that the signer chains to Apple's Device CA.  The caller must
/// provide that trust decision using the certificate chain included in the
/// CMS and its configured Apple trust anchors before assigning a profile.
pub fn parse_ade_machine_info(header: &str) -> Result<AdeMachineInfo> {
    if header.len() > MAX_HEADER_BLOB || header.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("ADE device-info header is invalid");
    }
    let cms_der = BASE64
        .decode(header)
        .context("decode ADE device-info header")?;
    parse_ade_machine_info_der_with_store(&cms_der, None)
}

/// Parses a raw DER CMS `MachineInfo` request from Apple's token-based ADE
/// POST flow.
pub fn parse_ade_machine_info_der(cms_der: &[u8]) -> Result<AdeMachineInfo> {
    parse_ade_machine_info_der_with_store(cms_der, None)
}

/// Parses and verifies an ADE CMS request against configured Apple trust
/// anchors.  `trust_anchor_pem` must contain at least one trusted Apple Device
/// CA certificate; accepting a signer merely because it is embedded in the
/// CMS is insufficient for enrollment authorization.
pub fn verify_ade_machine_info(header: &str, trust_anchor_pem: &[u8]) -> Result<AdeMachineInfo> {
    let certs = X509::stack_from_pem(trust_anchor_pem).context("parse ADE trust anchors")?;
    if certs.is_empty() || certs.len() > 64 {
        bail!("ADE trust anchors are empty or too numerous");
    }
    let mut builder = X509StoreBuilder::new().context("build ADE trust store")?;
    for cert in certs {
        builder.add_cert(cert).context("add ADE trust anchor")?;
    }
    let store = builder.build();
    if header.len() > MAX_HEADER_BLOB || header.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("ADE device-info header is invalid");
    }
    let cms_der = BASE64
        .decode(header)
        .context("decode ADE device-info header")?;
    parse_ade_machine_info_der_with_store(&cms_der, Some(&store))
}

/// Verifies a raw DER CMS `MachineInfo` request against Apple trust anchors.
pub fn verify_ade_machine_info_der(
    cms_der: &[u8],
    trust_anchor_pem: &[u8],
) -> Result<AdeMachineInfo> {
    let certs = X509::stack_from_pem(trust_anchor_pem).context("parse ADE trust anchors")?;
    if certs.is_empty() || certs.len() > 64 {
        bail!("ADE trust anchors are empty or too numerous");
    }
    let mut builder = X509StoreBuilder::new().context("build ADE trust store")?;
    for cert in certs {
        builder.add_cert(cert).context("add ADE trust anchor")?;
    }
    let store = builder.build();
    parse_ade_machine_info_der_with_store(cms_der, Some(&store))
}

fn parse_ade_machine_info_der_with_store(
    cms_der: &[u8],
    trust_store: Option<&openssl::x509::store::X509StoreRef>,
) -> Result<AdeMachineInfo> {
    if cms_der.is_empty() || cms_der.len() > MAX_HEADER_BLOB {
        bail!("ADE device-info CMS is empty or too large");
    }
    let mut cms = CmsContentInfo::from_der(cms_der).context("parse ADE device-info CMS")?;
    let mut clear = Vec::new();
    let flags = if trust_store.is_some() {
        openssl::cms::CMSOptions::empty()
    } else {
        openssl::cms::CMSOptions::NO_SIGNER_CERT_VERIFY
    };
    cms.verify(None, trust_store, None, Some(&mut clear), flags)
        .context("verify ADE device-info CMS signature")?;
    if clear.len() > MAX_HEADER_BLOB {
        bail!("ADE device-info plist is too large");
    }
    parse_machine_info_plist(&clear)
}

fn parse_machine_info_plist(bytes: &[u8]) -> Result<AdeMachineInfo> {
    let value =
        plist::Value::from_reader(Cursor::new(bytes)).context("parse ADE machine-info plist")?;
    let dictionary = match value {
        plist::Value::Dictionary(dictionary) => dictionary,
        _ => bail!("ADE machine-info plist must be a dictionary"),
    };
    let string = |key: &str| -> Result<Option<String>> {
        match dictionary.get(key) {
            None => Ok(None),
            Some(plist::Value::String(value)) => {
                validate_machine_string(value, key)?;
                Ok(Some(value.clone()))
            }
            Some(_) => bail!("ADE machine-info {key} must be a string"),
        }
    };
    let required = |key: &str| -> Result<String> {
        string(key)?.ok_or_else(|| anyhow!("ADE machine-info omits {key}"))
    };
    let serial = required("SERIAL")?;
    // Apple marks these MachineInfo values as required.  Do not silently
    // authorize a profile from a truncated plist that happens to contain a
    // serial number only.
    let udid = Some(required("UDID")?);
    let product = Some(required("PRODUCT")?);
    let version = Some(required("VERSION")?);
    let os_version = Some(required("OS_VERSION")?);
    Ok(AdeMachineInfo {
        serial,
        udid,
        product,
        version,
        os_version,
    })
}

fn validate_machine_string(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        bail!("ADE machine-info {name} is invalid");
    }
    Ok(())
}

fn build_ade_client(token: Arc<AdeServerToken>, base_url: Url) -> Result<AdeClient> {
    let client = Client::builder()
        .use_native_tls()
        .https_only(base_url.scheme() == "https")
        .redirect(Policy::none())
        .http2_adaptive_window(true)
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent("mdmd-apple-adapter/0.1")
        .build()
        .context("build ADE HTTP client")?;
    Ok(AdeClient {
        client,
        token,
        session: Arc::new(Mutex::new(None)),
        base_url,
    })
}

fn build_vpp_client(token: String, base_url: Url) -> Result<VppClient> {
    let client = Client::builder()
        .use_native_tls()
        .https_only(base_url.scheme() == "https")
        .redirect(Policy::none())
        .http2_adaptive_window(true)
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent("mdmd-apple-adapter/0.1")
        .build()
        .context("build Apps & Books HTTP client")?;
    Ok(VppClient {
        client,
        token,
        base_url,
    })
}

fn decrypt_cms(bytes: &[u8], key: &PKey<Private>, cert: &X509) -> Result<Vec<u8>> {
    let cms = if bytes.starts_with(b"-----BEGIN") {
        CmsContentInfo::from_pem(bytes)
            .or_else(|_| CmsContentInfo::smime_read_cms(bytes))
            .context("parse ADE encrypted token CMS")?
    } else {
        CmsContentInfo::from_der(bytes)
            .or_else(|_| CmsContentInfo::smime_read_cms(bytes))
            .context("parse ADE encrypted token CMS")?
    };
    cms.decrypt(key, cert)
        .context("decrypt ADE encrypted token CMS")
}

fn parse_ade_server_token(bytes: &[u8]) -> Result<AdeServerToken> {
    if bytes.len() > MAX_DECRYPTED_TOKEN {
        bail!("ADE server token is too large");
    }
    let payload = strip_mime_headers(bytes);
    let mut fields = BTreeMap::new();
    if let Ok(value) = serde_json::from_slice::<Value>(payload) {
        collect_token_fields(&value, &mut fields);
    }
    if fields.len() < 4
        && let Ok(value) = plist::Value::from_reader(Cursor::new(payload))
    {
        collect_plist_token_fields(&value, &mut fields);
    }
    let token = AdeServerToken {
        consumer_key: take_token_field(&fields, &["consumer_key", "consumerKey"])?,
        consumer_secret: take_token_field(&fields, &["consumer_secret", "consumerSecret"])?,
        access_token: take_token_field(&fields, &["access_token", "accessToken"])?,
        access_secret: take_token_field(&fields, &["access_secret", "accessSecret"])?,
    };
    validate_ade_token(token)
}

fn collect_token_fields(value: &Value, fields: &mut BTreeMap<String, String>) {
    if let Value::Object(object) = value {
        for (key, value) in object {
            if let Value::String(value) = value {
                fields.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
}

fn collect_plist_token_fields(value: &plist::Value, fields: &mut BTreeMap<String, String>) {
    if let plist::Value::Dictionary(dictionary) = value {
        for (key, value) in dictionary {
            if let plist::Value::String(value) = value {
                fields.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
}

fn take_token_field(fields: &BTreeMap<String, String>, names: &[&str]) -> Result<String> {
    for name in names {
        if let Some(value) = fields.get(*name) {
            return validate_secret_value(value.clone(), name);
        }
    }
    bail!("ADE server token omits required credential")
}

fn validate_ade_token(token: AdeServerToken) -> Result<AdeServerToken> {
    validate_secret(&token.consumer_key, "ADE consumer key")?;
    validate_secret(&token.consumer_secret, "ADE consumer secret")?;
    validate_secret(&token.access_token, "ADE access token")?;
    validate_secret(&token.access_secret, "ADE access secret")?;
    Ok(token)
}

fn oauth_authorization(
    token: &AdeServerToken,
    method: Method,
    url: &Url,
) -> Result<(String, String)> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before Unix epoch"))?
        .as_secs();
    let mut nonce_bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut nonce_bytes).context("generate ADE OAuth nonce")?;
    let nonce = hex::encode(nonce_bytes);
    let mut params = vec![
        ("oauth_consumer_key".to_owned(), token.consumer_key.clone()),
        ("oauth_nonce".to_owned(), nonce.clone()),
        ("oauth_signature_method".to_owned(), "HMAC-SHA1".to_owned()),
        ("oauth_timestamp".to_owned(), timestamp.to_string()),
        ("oauth_token".to_owned(), token.access_token.clone()),
        ("oauth_version".to_owned(), "1.0".to_owned()),
    ];
    for (key, value) in url.query_pairs() {
        params.push((key.into_owned(), value.into_owned()));
    }
    let normalized = normalized_oauth_params(&params);
    let base_uri = canonical_base_uri(url);
    let base_string = format!(
        "{}&{}&{}",
        method.as_str().to_uppercase(),
        oauth_percent_encode(&base_uri),
        oauth_percent_encode(&normalized)
    );
    let signing_key = format!(
        "{}&{}",
        oauth_percent_encode(&token.consumer_secret),
        oauth_percent_encode(&token.access_secret)
    );
    let key = PKey::hmac(signing_key.as_bytes()).context("build ADE OAuth signing key")?;
    let mut signer = Signer::new(MessageDigest::sha1(), &key).context("build ADE OAuth signer")?;
    signer
        .update(base_string.as_bytes())
        .context("sign ADE OAuth request")?;
    let signature = BASE64.encode(signer.sign_to_vec().context("finish ADE OAuth signature")?);
    params.push(("oauth_signature".to_owned(), signature));
    let mut authorization = String::from("OAuth realm=\"ADM\"");
    for (key, value) in params
        .into_iter()
        .filter(|(key, _)| key.starts_with("oauth_"))
    {
        authorization.push_str(", ");
        authorization.push_str(&oauth_percent_encode(&key));
        authorization.push_str("=\"");
        authorization.push_str(&oauth_percent_encode(&value));
        authorization.push('"');
    }
    Ok((authorization, base_string))
}

fn normalized_oauth_params(params: &[(String, String)]) -> String {
    let mut encoded = params
        .iter()
        .map(|(key, value)| (oauth_percent_encode(key), oauth_percent_encode(value)))
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_base_uri(url: &Url) -> String {
    let mut uri = format!(
        "{}://{}",
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or_default().to_ascii_lowercase()
    );
    if let Some(port) = url.port() {
        let default =
            (url.scheme() == "https" && port == 443) || (url.scheme() == "http" && port == 80);
        if !default {
            uri.push(':');
            uri.push_str(&port.to_string());
        }
    }
    uri.push_str(if url.path().is_empty() {
        "/"
    } else {
        url.path()
    });
    uri
}

fn oauth_percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(hex_char(byte >> 4));
            output.push(hex_char(byte & 0x0f));
        }
    }
    output
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

fn parse_device_page(value: Value) -> Result<AdeDevicePage> {
    let page: AdeDevicePage = serde_json::from_value(value).context("parse ADE device response")?;
    if page.devices.len() > MAX_SERIALS {
        bail!("ADE device response exceeds the supported page size");
    }
    if let Some(cursor) = &page.cursor
        && (cursor.len() > 4_096 || cursor.chars().any(char::is_control))
    {
        bail!("ADE device response cursor is invalid");
    }
    Ok(page)
}

fn validate_profile(profile: &Value) -> Result<()> {
    let object = profile
        .as_object()
        .ok_or_else(|| anyhow!("ADE profile must be a JSON object"))?;
    if object.is_empty() || profile.to_string().len() > MAX_JSON_BODY {
        bail!("ADE profile is empty or too large");
    }
    for key in ["url", "configuration_web_url"] {
        if let Some(value) = object.get(key) {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow!("ADE profile {key} must be a string"))?;
            validate_manifest_url(value).context("ADE profile URL")?;
        }
    }
    if let Some(anchor_certs) = object.get("anchor_certs") {
        let certs = anchor_certs
            .as_array()
            .ok_or_else(|| anyhow!("ADE profile anchor_certs must be an array"))?;
        if certs.len() > 16 {
            bail!("ADE profile has too many anchor certificates");
        }
        for cert in certs {
            let cert = cert
                .as_str()
                .ok_or_else(|| anyhow!("ADE profile anchor_certs must contain strings"))?;
            let der = BASE64
                .decode(cert)
                .map_err(|_| anyhow!("ADE profile anchor certificate is invalid"))?;
            if der.is_empty() || der.len() > 48 * 1024 || X509::from_der(&der).is_err() {
                bail!("ADE profile anchor certificate is invalid");
            }
        }
    }
    Ok(())
}

fn object_response(value: Value, context: &str) -> Result<AdeProfileResponse> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{context} response was not an object"))?;
    Ok(AdeProfileResponse {
        value: object.clone(),
    })
}

fn object_assignment(value: Value) -> Result<AdeProfileAssignment> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("ADE profile assignment response was not an object"))?;
    Ok(AdeProfileAssignment {
        value: object.clone(),
    })
}

fn validate_serials(serial_numbers: &[String]) -> Result<()> {
    if serial_numbers.is_empty() || serial_numbers.len() > MAX_SERIALS {
        bail!("serial number count must be between 1 and 1000");
    }
    for serial in serial_numbers {
        validate_identifier(serial, "Apple serial number", 128)?;
    }
    Ok(())
}

fn validate_identifier(value: &str, name: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("{name} is invalid");
    }
    Ok(())
}

fn insert_bounded_string(
    object: &mut Map<String, Value>,
    key: &str,
    value: &str,
    max: usize,
) -> Result<()> {
    validate_identifier(value, key, max)?;
    object.insert(key.to_owned(), Value::String(value.to_owned()));
    Ok(())
}

fn validate_secret(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        bail!("{name} is invalid");
    }
    Ok(())
}

fn validate_secret_value(value: String, name: &str) -> Result<String> {
    validate_secret(&value, name)?;
    Ok(value)
}

fn strip_mime_headers(bytes: &[u8]) -> &[u8] {
    for (separator, width) in [(b"\r\n\r\n".as_slice(), 4), (b"\n\n".as_slice(), 2)] {
        if let Some(index) = bytes
            .windows(separator.len())
            .position(|window| window == separator)
        {
            let payload = &bytes[index + width..];
            let trimmed = payload
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map(|start| &payload[start..])
                .unwrap_or(payload);
            if trimmed.starts_with(b"{") || trimmed.starts_with(b"<") {
                return trimmed;
            }
        }
    }
    bytes
}

fn join_api_path(base_url: &Url, path: &str) -> Url {
    let mut url = base_url.clone();
    let base_path = url.path().trim_end_matches('/');
    let endpoint_path = path.trim_start_matches('/');
    let joined = if base_path.is_empty() {
        format!("/{endpoint_path}")
    } else {
        format!("{base_path}/{endpoint_path}")
    };
    url.set_path(&joined);
    url
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("::1"))
}

fn parse_vpp_token(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes)
        .context("Apps & Books token is not UTF-8")?
        .trim();
    if text.starts_with('{') {
        let value: Value = serde_json::from_str(text).context("parse Apps & Books token JSON")?;
        for name in ["sToken", "s_token", "token", "content_token"] {
            if let Some(token) = value.get(name).and_then(Value::as_str) {
                return validate_secret_value(token.to_owned(), "Apps & Books token");
            }
        }
        bail!("Apps & Books token JSON omits token");
    }
    // Apple downloads the location-based sToken as a Base64-encoded JSON
    // object.  The complete encoded value is the bearer credential; the
    // decoded `token` member is metadata inside that credential and must not
    // be substituted for it.
    if let Ok(decoded) = BASE64.decode(text)
        && let Ok(value) = serde_json::from_slice::<Value>(&decoded)
        && value.get("token").and_then(Value::as_str).is_none()
    {
        bail!("Apps & Books Base64 token JSON omits token");
    }
    validate_secret_value(text.to_owned(), "Apps & Books token")
}

fn read_bounded_file(path: &Path, max: usize, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("stat {description}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() as usize > max {
        bail!("{description} must be a non-empty regular file of at most {max} bytes");
    }
    fs::read(path).with_context(|| format!("read {description}"))
}

fn read_private_file(path: &Path, max: usize, description: &str) -> Result<Vec<u8>> {
    let bytes = read_bounded_file(path, max, description)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("stat {description}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            bail!("{description} must have file mode 0600");
        }
    }
    Ok(bytes)
}

async fn bounded_json(mut response: reqwest::Response) -> Result<Value> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read Apple JSON response")? {
        if bytes.len().saturating_add(chunk.len()) > MAX_JSON_BODY {
            bail!("Apple JSON response is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("parse Apple JSON response")
}

fn discard_body(response: reqwest::Response) {
    drop(response);
}
