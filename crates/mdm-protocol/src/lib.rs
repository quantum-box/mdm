//! Bounded Apple MDM protocol primitives.
//!
//! The crate intentionally implements the device channel subset needed by the
//! first MDM engine: enrollment check-in, command responses, device-channel
//! declarative management, the supported legacy command families, and
//! enrollment/kiosk profiles.
//! User-channel messages and unsupported check-in message types are rejected
//! instead of being silently misinterpreted.

use std::{collections::BTreeMap, io::Cursor};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error as ThisError;
use uuid::Uuid;

/// Maximum XML/binary plist size accepted by check-in and response parsers.
pub const MAX_PLIST_BYTES: usize = 1024 * 1024;
/// Maximum configuration-profile size accepted by `InstallProfile`.
///
/// The management API accepts request bodies up to 2 MiB, while a profile is
/// deliberately kept smaller so its base64/JSON representation cannot consume
/// the entire request budget.
pub const MAX_PROFILE_BYTES: usize = 256 * 1024;
/// Maximum APNs device-token size accepted in a `TokenUpdate` message.
/// Apple tokens are variable length; this is a size bound, not a 32-byte shape
/// check.
pub const MAX_TOKEN_BYTES: usize = 256;
/// Maximum number of `DeviceInformation` queries in one command.
pub const MAX_QUERY_COUNT: usize = 128;
/// Maximum size of a single textual protocol field.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum size of a JSON document carried by a declarative-management
/// check-in or command.
pub const MAX_DDM_JSON_BYTES: usize = 1024 * 1024;
/// Maximum size Apple permits for a declarative declaration identifier or
/// server token in the manifest/declaration wire format.
pub const MAX_DDM_IDENTIFIER_BYTES: usize = 64;
/// Maximum size used for a DDM synchronization token.
pub const MAX_DDM_TOKEN_BYTES: usize = 256;

// AccessRights values from Apple's MDM payload schema.  The enrollment
// profile advertises the complete legacy device-channel set implemented by
// this crate; the server still decides which commands an administrator may
// enqueue.
pub const ACCESS_RIGHT_PROFILE_INSPECTION: i64 = 1;
pub const ACCESS_RIGHT_PROFILE_INSTALLATION_REMOVAL: i64 = 2;
pub const ACCESS_RIGHT_DEVICE_LOCK: i64 = 4;
pub const ACCESS_RIGHT_DEVICE_ERASE: i64 = 8;
pub const ACCESS_RIGHT_DEVICE_INFORMATION: i64 = 16;
pub const ACCESS_RIGHT_APPLICATION_INSPECTION: i64 = 256;
pub const ACCESS_RIGHT_APPLICATION_MANAGEMENT: i64 = 4096;
pub const ENROLLMENT_PROFILE_ACCESS_RIGHTS: i64 = ACCESS_RIGHT_PROFILE_INSPECTION
    | ACCESS_RIGHT_PROFILE_INSTALLATION_REMOVAL
    | ACCESS_RIGHT_DEVICE_LOCK
    | ACCESS_RIGHT_DEVICE_ERASE
    | ACCESS_RIGHT_DEVICE_INFORMATION
    | ACCESS_RIGHT_APPLICATION_INSPECTION
    | ACCESS_RIGHT_APPLICATION_MANAGEMENT;

/// Errors returned by the protocol helpers.
#[derive(Debug, ThisError)]
pub enum ProtocolError {
    #[error("{kind} input is too large: {actual} bytes (limit {limit})")]
    InputTooLarge {
        kind: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("invalid plist: {0}")]
    Plist(#[from] plist::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("top-level plist value must be a dictionary")]
    NotDictionary,
    #[error("missing required plist key `{0}`")]
    MissingKey(String),
    #[error("plist key `{key}` must contain {expected}")]
    InvalidType { key: String, expected: &'static str },
    #[error("invalid field `{field}`: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("unsupported check-in message type `{0}`")]
    UnsupportedMessageType(String),
    #[error("user-channel messages are unsupported")]
    UnsupportedChannel,
    #[error("unsupported device-information query `{0}`")]
    UnsupportedQuery(String),
    #[error("unsupported device response status `{0}`")]
    UnsupportedStatus(String),
    #[error("command UUID is empty or too long")]
    InvalidCommandUuid,
    #[error("InstallProfile payload must be a valid Configuration XML plist")]
    InvalidProfile,
    #[error("invalid enrollment profile: {0}")]
    InvalidEnrollmentProfile(&'static str),
    #[error("invalid CA certificate data: {0}")]
    InvalidCertificate(String),
}

/// Result type used by all public protocol functions.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Compatibility alias for callers that prefer the short error name.
pub use ProtocolError as Error;

/// A device-channel endpoint used by a declarative-management check-in.
///
/// The endpoint is kept as a typed value so callers do not need to parse
/// slash-separated paths themselves. The four declaration categories are the
/// categories defined by Apple's DDM protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeclarativeEndpoint {
    Tokens,
    DeclarationItems,
    Status,
    Declaration {
        kind: DeclarationKind,
        identifier: String,
    },
}

impl DeclarativeEndpoint {
    /// Parse Apple's endpoint path syntax.
    pub fn parse(endpoint: &str) -> Result<Self> {
        validate_text("Endpoint", endpoint)?;
        let mut segments = endpoint.split('/');
        let first = segments.next().unwrap_or_default();
        let endpoint = match (first, segments.next(), segments.next(), segments.next()) {
            ("tokens", None, None, None) => Self::Tokens,
            ("declaration-items", None, None, None) => Self::DeclarationItems,
            ("status", None, None, None) => Self::Status,
            ("declaration", Some(kind), Some(identifier), None) => Self::Declaration {
                kind: DeclarationKind::parse(kind)?,
                identifier: validate_declaration_identifier(identifier)?,
            },
            _ => {
                return Err(invalid_field(
                    "Endpoint",
                    "must be tokens, declaration-items, status, or a declaration path",
                ));
            }
        };
        Ok(endpoint)
    }

    /// Return the endpoint in Apple's wire-format path form.
    pub fn as_str(&self) -> String {
        match self {
            Self::Tokens => "tokens".into(),
            Self::DeclarationItems => "declaration-items".into(),
            Self::Status => "status".into(),
            Self::Declaration { kind, identifier } => {
                format!("declaration/{}/{identifier}", kind.as_str())
            }
        }
    }

    fn is_status(&self) -> bool {
        matches!(self, Self::Status)
    }
}

/// A DDM declaration category used in a declaration endpoint or manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclarationKind {
    Activation,
    Asset,
    Configuration,
    Management,
}

impl DeclarationKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "activation" => Ok(Self::Activation),
            "asset" => Ok(Self::Asset),
            "configuration" => Ok(Self::Configuration),
            "management" => Ok(Self::Management),
            _ => Err(invalid_field(
                "Endpoint",
                "declaration category must be activation, asset, configuration, or management",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Asset => "asset",
            Self::Configuration => "configuration",
            Self::Management => "management",
        }
    }
}

/// Synchronization tokens exchanged by the DDM command and check-in
/// endpoints. Field names intentionally follow Apple's JSON schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizationTokens {
    #[serde(rename = "DeclarationsToken")]
    pub declarations_token: String,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
}

impl SynchronizationTokens {
    pub fn validate(&self) -> Result<()> {
        validate_ddm_token("DeclarationsToken", &self.declarations_token)?;
        validate_ddm_timestamp(&self.timestamp)
    }
}

/// JSON body returned for the DDM `tokens` endpoint and sent as command data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensResponse {
    #[serde(rename = "SyncTokens")]
    pub sync_tokens: SynchronizationTokens,
}

impl TokensResponse {
    pub fn validate(&self) -> Result<()> {
        self.sync_tokens.validate()
    }
}

/// One declaration entry in a DDM declaration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDeclaration {
    #[serde(rename = "Identifier")]
    pub identifier: String,
    #[serde(rename = "ServerToken")]
    pub server_token: String,
}

impl ManifestDeclaration {
    pub fn validate(&self) -> Result<()> {
        validate_declaration_identifier(&self.identifier)?;
        validate_declaration_token(&self.server_token)
    }
}

/// The four required arrays in a DDM declaration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationManifest {
    #[serde(rename = "Activations")]
    pub activations: Vec<ManifestDeclaration>,
    #[serde(rename = "Configurations")]
    pub configurations: Vec<ManifestDeclaration>,
    #[serde(rename = "Assets")]
    pub assets: Vec<ManifestDeclaration>,
    #[serde(rename = "Management")]
    pub management: Vec<ManifestDeclaration>,
}

impl DeclarationManifest {
    pub fn validate(&self) -> Result<()> {
        for declaration in self
            .activations
            .iter()
            .chain(&self.configurations)
            .chain(&self.assets)
            .chain(&self.management)
        {
            declaration.validate()?;
        }
        Ok(())
    }
}

/// JSON body returned for the DDM `declaration-items` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationItemsResponse {
    #[serde(rename = "Declarations")]
    pub declarations: DeclarationManifest,
    #[serde(rename = "DeclarationsToken")]
    pub declarations_token: String,
}

impl DeclarationItemsResponse {
    pub fn validate(&self) -> Result<()> {
        self.declarations.validate()?;
        validate_ddm_token("DeclarationsToken", &self.declarations_token)
    }
}

/// One error entry in a DDM status report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusError {
    #[serde(rename = "StatusItem")]
    pub status_item: String,
    #[serde(rename = "Reasons", default)]
    pub reasons: Vec<StatusReason>,
}

impl StatusError {
    fn validate(&self) -> Result<()> {
        validate_text("StatusItem", &self.status_item)?;
        for reason in &self.reasons {
            reason.validate()?;
        }
        Ok(())
    }
}

/// One reason associated with an error in a DDM status report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReason {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "Details", default)]
    pub details: Option<BTreeMap<String, JsonValue>>,
}

impl StatusReason {
    fn validate(&self) -> Result<()> {
        validate_text("Code", &self.code)?;
        if let Some(description) = &self.description {
            validate_text("Description", description)?;
        }
        Ok(())
    }
}

/// JSON body sent by a device to the DDM `status` endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    #[serde(rename = "StatusItems")]
    pub status_items: BTreeMap<String, JsonValue>,
    #[serde(rename = "Errors")]
    pub errors: Vec<StatusError>,
    #[serde(rename = "FullReport", default)]
    pub full_report: bool,
}

impl StatusReport {
    pub fn validate(&self) -> Result<()> {
        for key in self.status_items.keys() {
            validate_text("StatusItems key", key)?;
        }
        for error in &self.errors {
            error.validate()?;
        }
        Ok(())
    }
}

/// Parse a DDM JSON response after applying the protocol size and shape
/// bounds. The dedicated response types below add schema-required fields.
pub fn parse_tokens_response(input: &[u8]) -> Result<TokensResponse> {
    let response: TokensResponse = parse_json(input, "tokens response")?;
    response.validate()?;
    Ok(response)
}

/// Parse a DDM declaration manifest response.
pub fn parse_declaration_items_response(input: &[u8]) -> Result<DeclarationItemsResponse> {
    let response: DeclarationItemsResponse = parse_json(input, "declaration-items response")?;
    response.validate()?;
    Ok(response)
}

/// Parse a DDM status report.
pub fn parse_status_report(input: &[u8]) -> Result<StatusReport> {
    let report: StatusReport = parse_json(input, "status report")?;
    report.validate()?;
    Ok(report)
}

fn parse_json<T: for<'de> Deserialize<'de>>(input: &[u8], kind: &'static str) -> Result<T> {
    if input.is_empty() {
        return Err(invalid_field(kind, "must not be empty"));
    }
    if input.len() > MAX_DDM_JSON_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind,
            actual: input.len(),
            limit: MAX_DDM_JSON_BYTES,
        });
    }
    Ok(serde_json::from_slice(input)?)
}

/// A device-channel check-in message.
#[derive(Clone, PartialEq, Eq)]
pub enum CheckIn {
    Authenticate {
        udid: String,
        topic: String,
        serial_number: Option<String>,
        os_version: Option<String>,
    },
    TokenUpdate {
        udid: String,
        topic: String,
        token: Vec<u8>,
        push_magic: String,
        unlock_token: Option<Vec<u8>>,
        awaiting_configuration: bool,
    },
    CheckOut {
        udid: String,
    },
    /// A device-channel declarative-management request. User-channel DDM
    /// check-ins are rejected by `parse_checkin` because this crate exposes a
    /// device-only API.
    DeclarativeManagement {
        udid: String,
        endpoint: DeclarativeEndpoint,
        data: Option<JsonValue>,
    },
}

/// Parse an Apple XML or binary plist check-in message.
pub fn parse_checkin(input: &[u8]) -> Result<CheckIn> {
    let value = parse_plist(input, "check-in", MAX_PLIST_BYTES)?;
    let dict = value.as_dictionary().ok_or(ProtocolError::NotDictionary)?;
    reject_user_channel(dict)?;

    let message_type = required_string(dict, "MessageType")?;
    match message_type.as_str() {
        "Authenticate" => Ok(CheckIn::Authenticate {
            udid: required_string(dict, "UDID")?,
            topic: required_topic(dict, "Topic")?,
            serial_number: optional_string(dict, "SerialNumber")?,
            os_version: optional_string(dict, "OSVersion")?,
        }),
        "TokenUpdate" => {
            let token = required_data(dict, "Token")?;
            if token.is_empty() {
                return Err(invalid_field("Token", "must not be empty"));
            }
            if token.len() > MAX_TOKEN_BYTES {
                return Err(ProtocolError::InputTooLarge {
                    kind: "APNs device token",
                    actual: token.len(),
                    limit: MAX_TOKEN_BYTES,
                });
            }
            let push_magic = required_string(dict, "PushMagic")?;
            let awaiting_configuration =
                optional_boolean(dict, "AwaitingConfiguration")?.unwrap_or(false);
            let unlock_token = optional_data(dict, "UnlockToken")?;
            Ok(CheckIn::TokenUpdate {
                udid: required_string(dict, "UDID")?,
                topic: required_topic(dict, "Topic")?,
                token,
                push_magic,
                unlock_token,
                awaiting_configuration,
            })
        }
        "CheckOut" => Ok(CheckIn::CheckOut {
            udid: required_string(dict, "UDID")?,
        }),
        "DeclarativeManagement" => parse_declarative_management(dict),
        other => Err(ProtocolError::UnsupportedMessageType(other.to_owned())),
    }
}

fn parse_declarative_management(dict: &Dictionary) -> Result<CheckIn> {
    let udid = required_string(dict, "UDID")?;
    let endpoint = DeclarativeEndpoint::parse(&required_string(dict, "Endpoint")?)?;
    let data = optional_data(dict, "Data")?;
    let data = match (endpoint.is_status(), data) {
        (true, Some(data)) => {
            if data.len() > MAX_DDM_JSON_BYTES {
                return Err(ProtocolError::InputTooLarge {
                    kind: "declarative-management JSON",
                    actual: data.len(),
                    limit: MAX_DDM_JSON_BYTES,
                });
            }
            // Validate the status envelope while retaining the original JSON
            // value for the HTTP layer and for audit storage.
            let _: StatusReport = parse_status_report(&data)?;
            Some(serde_json::from_slice::<JsonValue>(&data)?)
        }
        (true, None) => return Err(ProtocolError::MissingKey("Data".into())),
        (false, Some(_)) => {
            return Err(invalid_field(
                "Data",
                "must be absent for this declarative-management endpoint",
            ));
        }
        (false, None) => None,
    };
    Ok(CheckIn::DeclarativeManagement {
        udid,
        endpoint,
        data,
    })
}

/// Status values emitted by an Apple device in a command response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Idle,
    Acknowledged,
    Error,
    CommandFormatError,
    NotNow,
}

/// A device-channel command response, preserving the original plist.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceResponse {
    pub udid: String,
    pub command_uuid: Option<String>,
    pub status: ResponseStatus,
    pub raw: Value,
}

/// Parse an Apple device-channel command response.
pub fn parse_response(input: &[u8]) -> Result<DeviceResponse> {
    let raw = parse_plist(input, "response", MAX_PLIST_BYTES)?;
    let dict = raw.as_dictionary().ok_or(ProtocolError::NotDictionary)?;
    reject_user_channel(dict)?;

    let udid = required_string(dict, "UDID")?;
    let status_string = required_string(dict, "Status")?;
    let status = match status_string.as_str() {
        "Idle" => ResponseStatus::Idle,
        "Acknowledged" => ResponseStatus::Acknowledged,
        "Error" => ResponseStatus::Error,
        "CommandFormatError" => ResponseStatus::CommandFormatError,
        "NotNow" => ResponseStatus::NotNow,
        other => return Err(ProtocolError::UnsupportedStatus(other.to_owned())),
    };
    let command_uuid = if status == ResponseStatus::Idle {
        if dict.contains_key("CommandUUID") {
            return Err(invalid_field(
                "CommandUUID",
                "must be absent for an Idle response",
            ));
        }
        None
    } else {
        Some(required_string(dict, "CommandUUID")?)
    };
    Ok(DeviceResponse {
        udid,
        command_uuid,
        status,
        raw,
    })
}

/// The restricted sources accepted by the legacy `InstallApplication`
/// command.  Device-based App Store licensing uses `PurchaseMethod=1`; an
/// enterprise app uses an HTTPS manifest URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplicationInstallSource {
    AppStore {
        itunes_store_id: u64,
        /// Apple’s device-based license assignment value (`1`).
        purchase_method: u8,
    },
    Enterprise {
        manifest_url: String,
    },
}

/// A single legacy operating-system update request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsUpdate {
    pub product_key: Option<String>,
    pub product_version: Option<String>,
    pub install_action: OsInstallAction,
    pub max_user_deferrals: Option<u64>,
    pub priority: Option<OsUpdatePriority>,
}

/// The `InstallAction` values in Apple’s `ScheduleOSUpdate` schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsInstallAction {
    #[serde(rename = "Default")]
    Default,
    #[serde(rename = "DownloadOnly")]
    DownloadOnly,
    #[serde(rename = "InstallASAP")]
    InstallAsap,
    #[serde(rename = "NotifyOnly")]
    NotifyOnly,
    #[serde(rename = "InstallLater")]
    InstallLater,
    #[serde(rename = "InstallForceRestart")]
    InstallForceRestart,
}

/// Scheduling priorities for macOS minor updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsUpdatePriority {
    #[serde(rename = "Low")]
    Low,
    #[serde(rename = "High")]
    High,
}

/// Fallback behavior for macOS `EraseDevice` when Erase All Content and
/// Settings cannot complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObliterationBehavior {
    #[serde(rename = "Default")]
    Default,
    #[serde(rename = "DoNotObliterate")]
    DoNotObliterate,
    #[serde(rename = "ObliterateWithWarning")]
    ObliterateWithWarning,
    #[serde(rename = "Always")]
    Always,
}

/// The legacy App Lock configuration profile used for supervised iOS/iPadOS
/// kiosk mode.  The UUID is supplied by the caller so retries produce byte
/// stable profile content.
pub fn kiosk_profile(
    bundle_id: &str,
    profile_identifier: &str,
    profile_uuid: &str,
) -> Result<Vec<u8>> {
    validate_text("bundle_id", bundle_id)?;
    validate_text("profile_identifier", profile_identifier)?;
    let profile_uuid = Uuid::parse_str(profile_uuid)
        .map_err(|_| invalid_field("profile_uuid", "must be a UUID"))?;

    let app_payload_uuid = derived_profile_uuid(profile_uuid, 1);
    let mut app_payload = common_payload(
        &format!("{profile_identifier}.app-lock"),
        &app_payload_uuid,
        "com.apple.app.lock",
        "MDM",
    );
    let mut app = Dictionary::new();
    app.insert("Identifier".into(), Value::String(bundle_id.to_owned()));
    app_payload.insert("App".into(), Value::Dictionary(app));

    let mut top = common_payload(
        profile_identifier,
        &profile_uuid.to_string(),
        "Configuration",
        "MDM",
    );
    top.insert(
        "PayloadDisplayName".into(),
        Value::String("MDM Kiosk".into()),
    );
    top.insert(
        "PayloadContent".into(),
        Value::Array(vec![Value::Dictionary(app_payload)]),
    );

    let mut output = Vec::new();
    Value::Dictionary(top).to_writer_xml(&mut output)?;
    Ok(output)
}

/// Alias emphasizing the underlying Apple payload name.
pub fn app_lock_profile(
    bundle_id: &str,
    profile_identifier: &str,
    profile_uuid: &str,
) -> Result<Vec<u8>> {
    kiosk_profile(bundle_id, profile_identifier, profile_uuid)
}

fn derived_profile_uuid(base: Uuid, discriminator: u8) -> String {
    let mut bytes = *base.as_bytes();
    bytes[15] ^= discriminator;
    Uuid::from_bytes(bytes).to_string()
}

/// The supported device-channel command payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandPayload {
    DeviceInformation {
        queries: Vec<String>,
    },
    InstallProfile {
        payload: Vec<u8>,
    },
    RemoveProfile {
        identifier: String,
    },
    /// Install a device-licensed App Store app or an HTTPS enterprise app.
    InstallApplication {
        source: ApplicationInstallSource,
    },
    /// Remove a managed application by bundle identifier.
    RemoveApplication {
        identifier: String,
    },
    /// Query installed applications, optionally limiting identifiers and
    /// response fields to reduce device-side work and returned data.
    InstalledApplicationList {
        identifiers: Option<Vec<String>>,
        #[serde(default)]
        managed_apps_only: bool,
        items: Option<Vec<String>>,
    },
    /// Query the status of managed applications from the App Store.
    ManagedApplicationList {
        identifiers: Option<Vec<String>>,
    },
    /// Query available operating-system updates. Apple has deprecated this
    /// command on newer releases in favor of DDM software-update declarations.
    #[serde(rename = "available_os_updates")]
    AvailableOSUpdates,
    /// Schedule one or more legacy operating-system update actions.
    #[serde(rename = "schedule_os_update")]
    ScheduleOSUpdate {
        updates: Vec<OsUpdate>,
    },
    /// Query legacy operating-system update status.
    #[serde(rename = "os_update_status")]
    OSUpdateStatus,
    /// Immediately lock a device.
    DeviceLock {
        message: Option<String>,
        phone_number: Option<String>,
        pin: Option<String>,
    },
    /// Immediately erase a device. The storage layer must apply its own
    /// durable confirmation policy before enqueueing this destructive command.
    EraseDevice {
        #[serde(default)]
        preserve_data_plan: bool,
        #[serde(default)]
        disallow_proximity_setup: bool,
        pin: Option<String>,
        obliteration_behavior: Option<ObliterationBehavior>,
    },
    /// Release an ADE device from Setup Assistant's await-configuration
    /// state. This command has no payload fields.
    DeviceConfigured,
    /// Enable or synchronize declarative management. The optional value is
    /// Apple's `TokensResponse` JSON object and is encoded as plist `<data>`.
    DeclarativeManagement {
        data: Option<JsonValue>,
    },
}

impl CommandPayload {
    /// Validate the command fields without encoding them.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::DeviceInformation { queries } => {
                if queries.is_empty() {
                    return Err(invalid_field("queries", "must contain at least one query"));
                }
                if queries.len() > MAX_QUERY_COUNT {
                    return Err(ProtocolError::InputTooLarge {
                        kind: "DeviceInformation queries",
                        actual: queries.len(),
                        limit: MAX_QUERY_COUNT,
                    });
                }
                for query in queries {
                    if query.len() > MAX_TEXT_BYTES {
                        return Err(ProtocolError::InputTooLarge {
                            kind: "DeviceInformation query",
                            actual: query.len(),
                            limit: MAX_TEXT_BYTES,
                        });
                    }
                    if !is_known_query(query) {
                        return Err(ProtocolError::UnsupportedQuery(query.clone()));
                    }
                }
            }
            Self::InstallProfile { payload } => {
                if payload.is_empty() {
                    return Err(invalid_field("payload", "must not be empty"));
                }
                if payload.len() > MAX_PROFILE_BYTES {
                    return Err(ProtocolError::InputTooLarge {
                        kind: "configuration profile",
                        actual: payload.len(),
                        limit: MAX_PROFILE_BYTES,
                    });
                }
                let value = Value::from_reader_xml(Cursor::new(payload))
                    .map_err(|_| ProtocolError::InvalidProfile)?;
                validate_configuration_profile(&value)?;
            }
            Self::RemoveProfile { identifier } => {
                validate_text("identifier", identifier)?;
            }
            Self::InstallApplication { source } => validate_application_source(source)?,
            Self::RemoveApplication { identifier } => {
                validate_text("identifier", identifier)?;
            }
            Self::InstalledApplicationList {
                identifiers,
                managed_apps_only: _,
                items,
            } => {
                validate_identifier_list("Identifiers", identifiers.as_deref())?;
                if let Some(items) = items {
                    if items.len() > MAX_QUERY_COUNT {
                        return Err(ProtocolError::InputTooLarge {
                            kind: "InstalledApplicationList items",
                            actual: items.len(),
                            limit: MAX_QUERY_COUNT,
                        });
                    }
                    for item in items {
                        if !is_known_installed_application_item(item) {
                            return Err(invalid_field(
                                "Items",
                                "contains an unsupported installed-application field",
                            ));
                        }
                    }
                }
            }
            Self::ManagedApplicationList { identifiers } => {
                validate_identifier_list("Identifiers", identifiers.as_deref())?;
            }
            Self::AvailableOSUpdates | Self::OSUpdateStatus => {}
            Self::ScheduleOSUpdate { updates } => {
                if updates.is_empty() {
                    return Err(invalid_field("Updates", "must not be empty"));
                }
                if updates.len() > MAX_QUERY_COUNT {
                    return Err(ProtocolError::InputTooLarge {
                        kind: "ScheduleOSUpdate updates",
                        actual: updates.len(),
                        limit: MAX_QUERY_COUNT,
                    });
                }
                for update in updates {
                    validate_os_update(update)?;
                }
            }
            Self::DeviceLock {
                message,
                phone_number,
                pin,
            } => {
                if let Some(message) = message {
                    validate_text("Message", message)?;
                }
                if let Some(phone_number) = phone_number {
                    validate_text("PhoneNumber", phone_number)?;
                }
                if let Some(pin) = pin {
                    validate_pin(pin)?;
                }
            }
            Self::EraseDevice {
                preserve_data_plan: _,
                disallow_proximity_setup: _,
                pin,
                obliteration_behavior: _,
            } => {
                if let Some(pin) = pin {
                    validate_pin(pin)?;
                }
            }
            Self::DeviceConfigured => {}
            Self::DeclarativeManagement { data } => {
                if let Some(data) = data {
                    let encoded = serde_json::to_vec(data)?;
                    let _: TokensResponse = parse_tokens_response(&encoded)?;
                }
            }
        }
        Ok(())
    }
}

/// Encode a device-channel MDM command as an XML plist.
pub fn encode_command(uuid: &str, payload: &CommandPayload) -> Result<Vec<u8>> {
    if uuid.is_empty() || uuid.len() > MAX_TEXT_BYTES || uuid.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidCommandUuid);
    }
    payload.validate()?;

    let mut command = Dictionary::new();
    match payload {
        CommandPayload::DeviceInformation { queries } => {
            command.insert(
                "RequestType".into(),
                Value::String("DeviceInformation".into()),
            );
            command.insert(
                "Queries".into(),
                Value::Array(queries.iter().cloned().map(Value::String).collect()),
            );
        }
        CommandPayload::InstallProfile { payload } => {
            command.insert("RequestType".into(), Value::String("InstallProfile".into()));
            command.insert("Payload".into(), Value::Data(payload.clone()));
        }
        CommandPayload::RemoveProfile { identifier } => {
            command.insert("RequestType".into(), Value::String("RemoveProfile".into()));
            command.insert("Identifier".into(), Value::String(identifier.clone()));
        }
        CommandPayload::InstallApplication { source } => {
            command.insert(
                "RequestType".into(),
                Value::String("InstallApplication".into()),
            );
            match source {
                ApplicationInstallSource::AppStore {
                    itunes_store_id,
                    purchase_method,
                } => {
                    command.insert(
                        "iTunesStoreID".into(),
                        Value::Integer(
                            i64::try_from(*itunes_store_id)
                                .map_err(|_| {
                                    invalid_field("iTunesStoreID", "must fit in a plist integer")
                                })?
                                .into(),
                        ),
                    );
                    let mut options = Dictionary::new();
                    options.insert(
                        "PurchaseMethod".into(),
                        Value::Integer(i64::from(*purchase_method).into()),
                    );
                    command.insert("Options".into(), Value::Dictionary(options));
                }
                ApplicationInstallSource::Enterprise { manifest_url } => {
                    command.insert("ManifestURL".into(), Value::String(manifest_url.clone()));
                }
            }
        }
        CommandPayload::RemoveApplication { identifier } => {
            command.insert(
                "RequestType".into(),
                Value::String("RemoveApplication".into()),
            );
            command.insert("Identifier".into(), Value::String(identifier.clone()));
        }
        CommandPayload::InstalledApplicationList {
            identifiers,
            managed_apps_only,
            items,
        } => {
            command.insert(
                "RequestType".into(),
                Value::String("InstalledApplicationList".into()),
            );
            if let Some(identifiers) = identifiers {
                command.insert(
                    "Identifiers".into(),
                    Value::Array(identifiers.iter().cloned().map(Value::String).collect()),
                );
            }
            command.insert("ManagedAppsOnly".into(), Value::Boolean(*managed_apps_only));
            if let Some(items) = items {
                command.insert(
                    "Items".into(),
                    Value::Array(items.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        CommandPayload::ManagedApplicationList { identifiers } => {
            command.insert(
                "RequestType".into(),
                Value::String("ManagedApplicationList".into()),
            );
            if let Some(identifiers) = identifiers {
                command.insert(
                    "Identifiers".into(),
                    Value::Array(identifiers.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        CommandPayload::AvailableOSUpdates => {
            command.insert(
                "RequestType".into(),
                Value::String("AvailableOSUpdates".into()),
            );
        }
        CommandPayload::ScheduleOSUpdate { updates } => {
            command.insert(
                "RequestType".into(),
                Value::String("ScheduleOSUpdate".into()),
            );
            command.insert(
                "Updates".into(),
                Value::Array(
                    updates
                        .iter()
                        .map(encode_os_update)
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .map(Value::Dictionary)
                        .collect(),
                ),
            );
        }
        CommandPayload::OSUpdateStatus => {
            command.insert("RequestType".into(), Value::String("OSUpdateStatus".into()));
        }
        CommandPayload::DeviceLock {
            message,
            phone_number,
            pin,
        } => {
            command.insert("RequestType".into(), Value::String("DeviceLock".into()));
            if let Some(message) = message {
                command.insert("Message".into(), Value::String(message.clone()));
            }
            if let Some(phone_number) = phone_number {
                command.insert("PhoneNumber".into(), Value::String(phone_number.clone()));
            }
            if let Some(pin) = pin {
                command.insert("PIN".into(), Value::String(pin.clone()));
            }
        }
        CommandPayload::EraseDevice {
            preserve_data_plan,
            disallow_proximity_setup,
            pin,
            obliteration_behavior,
        } => {
            command.insert("RequestType".into(), Value::String("EraseDevice".into()));
            if *preserve_data_plan {
                command.insert("PreserveDataPlan".into(), Value::Boolean(true));
            }
            if *disallow_proximity_setup {
                command.insert("DisallowProximitySetup".into(), Value::Boolean(true));
            }
            if let Some(pin) = pin {
                command.insert("PIN".into(), Value::String(pin.clone()));
            }
            if let Some(behavior) = obliteration_behavior {
                command.insert(
                    "ObliterationBehavior".into(),
                    Value::String(obliteration_behavior_string(*behavior).into()),
                );
            }
        }
        CommandPayload::DeviceConfigured => {
            command.insert(
                "RequestType".into(),
                Value::String("DeviceConfigured".into()),
            );
        }
        CommandPayload::DeclarativeManagement { data } => {
            command.insert(
                "RequestType".into(),
                Value::String("DeclarativeManagement".into()),
            );
            if let Some(data) = data {
                command.insert("Data".into(), Value::Data(serde_json::to_vec(data)?));
            }
        }
    }

    let mut root = Dictionary::new();
    root.insert("Command".into(), Value::Dictionary(command));
    root.insert("CommandUUID".into(), Value::String(uuid.to_owned()));
    let mut output = Vec::new();
    Value::Dictionary(root).to_writer_xml(&mut output)?;
    Ok(output)
}

/// Values needed to build a device enrollment profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProfile {
    pub public_url: String,
    pub topic: String,
    pub challenge: String,
    pub enrollment_id: String,
    pub ca_certificate: Vec<u8>,
    pub organization: String,
}

/// Build an XML configuration profile containing root CA, SCEP, and MDM
/// payloads for a device-channel enrollment.
pub fn enrollment_profile(profile: &EnrollmentProfile) -> Result<Vec<u8>> {
    let public_url = validate_public_url(&profile.public_url)?;
    validate_topic(&profile.topic)?;
    validate_text("enrollment_id", &profile.enrollment_id)?;
    validate_text("organization", &profile.organization)?;
    if profile.ca_certificate.is_empty() {
        return Err(ProtocolError::InvalidEnrollmentProfile(
            "ca_certificate must not be empty",
        ));
    }
    if profile.ca_certificate.len() > MAX_PROFILE_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "CA certificate",
            actual: profile.ca_certificate.len(),
            limit: MAX_PROFILE_BYTES,
        });
    }
    if profile.challenge.len() > MAX_TEXT_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "SCEP challenge",
            actual: profile.challenge.len(),
            limit: MAX_TEXT_BYTES,
        });
    }
    if profile.challenge.chars().any(char::is_control) {
        return Err(invalid_field(
            "challenge",
            "must not contain control characters",
        ));
    }

    let ca_certificate = decode_pem_certificate(&profile.ca_certificate)?;
    let root_uuid = Uuid::new_v4().to_string();
    let scep_uuid = Uuid::new_v4().to_string();
    let mdm_uuid = Uuid::new_v4().to_string();
    let profile_uuid = Uuid::new_v4().to_string();
    let identifier_base = format!("com.apple.mdm.{}", profile.enrollment_id);

    let mut root = common_payload(
        &format!("{identifier_base}.root"),
        &root_uuid,
        "com.apple.security.root",
        &profile.organization,
    );
    root.insert(
        "PayloadCertificateFileName".into(),
        Value::String("mdm-ca.cer".into()),
    );
    root.insert("PayloadContent".into(), Value::Data(ca_certificate));

    let mut scep_content = Dictionary::new();
    scep_content.insert("URL".into(), Value::String(format!("{public_url}/scep")));
    scep_content.insert(
        "Subject".into(),
        Value::Array(vec![Value::Array(vec![Value::Array(vec![
            Value::String("CN".into()),
            Value::String(profile.enrollment_id.clone()),
        ])])]),
    );
    if !profile.challenge.is_empty() {
        scep_content.insert("Challenge".into(), Value::String(profile.challenge.clone()));
    }
    scep_content.insert("Keysize".into(), Value::Integer(2048.into()));
    scep_content.insert("Key Type".into(), Value::String("RSA".into()));

    let mut scep = common_payload(
        &format!("{identifier_base}.scep"),
        &scep_uuid,
        "com.apple.security.scep",
        &profile.organization,
    );
    scep.insert("PayloadContent".into(), Value::Dictionary(scep_content));

    let mut mdm = common_payload(
        &format!("{identifier_base}.mdm"),
        &mdm_uuid,
        "com.apple.mdm",
        &profile.organization,
    );
    mdm.insert("IdentityCertificateUUID".into(), Value::String(scep_uuid));
    mdm.insert("Topic".into(), Value::String(profile.topic.clone()));
    mdm.insert(
        "ServerURL".into(),
        Value::String(format!("{public_url}/mdm")),
    );
    mdm.insert(
        "CheckInURL".into(),
        Value::String(format!("{public_url}/checkin")),
    );
    // Apple MDM AccessRights: profile inspection/install, lock, erase,
    // device information, application inspection, and app management.
    mdm.insert(
        "AccessRights".into(),
        Value::Integer(ENROLLMENT_PROFILE_ACCESS_RIGHTS.into()),
    );
    mdm.insert("CheckOutWhenRemoved".into(), Value::Boolean(true));

    let mut top = Dictionary::new();
    top.insert(
        "PayloadContent".into(),
        Value::Array(vec![
            Value::Dictionary(root),
            Value::Dictionary(scep),
            Value::Dictionary(mdm),
        ]),
    );
    top.insert(
        "PayloadDisplayName".into(),
        Value::String(format!("{} MDM", profile.organization)),
    );
    top.insert(
        "PayloadOrganization".into(),
        Value::String(profile.organization.clone()),
    );
    top.insert(
        "PayloadIdentifier".into(),
        Value::String(format!("{identifier_base}.profile")),
    );
    top.insert("PayloadUUID".into(), Value::String(profile_uuid));
    top.insert("PayloadType".into(), Value::String("Configuration".into()));
    top.insert("PayloadVersion".into(), Value::Integer(1.into()));

    let mut output = Vec::new();
    Value::Dictionary(top).to_writer_xml(&mut output)?;
    Ok(output)
}

fn validate_configuration_profile(value: &Value) -> Result<()> {
    let dictionary = value.as_dictionary().ok_or(ProtocolError::InvalidProfile)?;

    let payload_type = dictionary
        .get("PayloadType")
        .and_then(Value::as_string)
        .ok_or(ProtocolError::InvalidProfile)?;
    if payload_type != "Configuration" {
        return Err(ProtocolError::InvalidProfile);
    }

    let identifier = dictionary
        .get("PayloadIdentifier")
        .and_then(Value::as_string)
        .ok_or(ProtocolError::InvalidProfile)?;
    validate_text("PayloadIdentifier", identifier).map_err(|_| ProtocolError::InvalidProfile)?;

    let payload_uuid = dictionary
        .get("PayloadUUID")
        .and_then(Value::as_string)
        .ok_or(ProtocolError::InvalidProfile)?;
    if Uuid::parse_str(payload_uuid).is_err() {
        return Err(ProtocolError::InvalidProfile);
    }

    let payload_version = dictionary
        .get("PayloadVersion")
        .and_then(Value::as_unsigned_integer)
        .ok_or(ProtocolError::InvalidProfile)?;
    if payload_version != 1 {
        return Err(ProtocolError::InvalidProfile);
    }

    let payload_content = dictionary
        .get("PayloadContent")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidProfile)?;
    if payload_content
        .iter()
        .any(|payload| payload.as_dictionary().is_none())
    {
        return Err(ProtocolError::InvalidProfile);
    }

    Ok(())
}

fn common_payload(
    identifier: &str,
    uuid: &str,
    payload_type: &str,
    organization: &str,
) -> Dictionary {
    let mut payload = Dictionary::new();
    payload.insert(
        "PayloadIdentifier".into(),
        Value::String(identifier.to_owned()),
    );
    payload.insert("PayloadUUID".into(), Value::String(uuid.to_owned()));
    payload.insert("PayloadType".into(), Value::String(payload_type.to_owned()));
    payload.insert("PayloadVersion".into(), Value::Integer(1.into()));
    payload.insert(
        "PayloadOrganization".into(),
        Value::String(organization.to_owned()),
    );
    payload
}

fn parse_plist(input: &[u8], kind: &'static str, limit: usize) -> Result<Value> {
    if input.is_empty() {
        return Err(ProtocolError::InvalidField {
            field: kind.to_owned(),
            reason: "must not be empty".into(),
        });
    }
    if input.len() > limit {
        return Err(ProtocolError::InputTooLarge {
            kind,
            actual: input.len(),
            limit,
        });
    }
    Ok(Value::from_reader(Cursor::new(input))?)
}

fn reject_user_channel(dict: &Dictionary) -> Result<()> {
    // EnrollmentID is only meaningful for user-enrollment flows, and this
    // crate deliberately exposes a device-channel-only API.
    const USER_CHANNEL_KEYS: &[&str] = &[
        "EnrollmentID",
        "EnrollmentUserID",
        "UserID",
        "UserShortName",
        "UserLongName",
        "UserChannel",
    ];
    if USER_CHANNEL_KEYS.iter().any(|key| dict.contains_key(key)) {
        return Err(ProtocolError::UnsupportedChannel);
    }
    Ok(())
}

fn required_string(dict: &Dictionary, key: &str) -> Result<String> {
    let value = dict
        .get(key)
        .ok_or_else(|| ProtocolError::MissingKey(key.to_owned()))?;
    let string = value
        .as_string()
        .ok_or_else(|| ProtocolError::InvalidType {
            key: key.to_owned(),
            expected: "a string",
        })?;
    validate_text(key, string)?;
    Ok(string.to_owned())
}

fn optional_string(dict: &Dictionary, key: &str) -> Result<Option<String>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    let string = value
        .as_string()
        .ok_or_else(|| ProtocolError::InvalidType {
            key: key.to_owned(),
            expected: "a string",
        })?;
    validate_text(key, string)?;
    Ok(Some(string.to_owned()))
}

fn required_data(dict: &Dictionary, key: &str) -> Result<Vec<u8>> {
    let value = dict
        .get(key)
        .ok_or_else(|| ProtocolError::MissingKey(key.to_owned()))?;
    value
        .as_data()
        .map(ToOwned::to_owned)
        .ok_or_else(|| ProtocolError::InvalidType {
            key: key.to_owned(),
            expected: "binary data",
        })
}

fn optional_data(dict: &Dictionary, key: &str) -> Result<Option<Vec<u8>>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .as_data()
        .map(|data| Some(data.to_owned()))
        .ok_or_else(|| ProtocolError::InvalidType {
            key: key.to_owned(),
            expected: "binary data",
        })
}

fn optional_boolean(dict: &Dictionary, key: &str) -> Result<Option<bool>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .as_boolean()
        .ok_or_else(|| ProtocolError::InvalidType {
            key: key.to_owned(),
            expected: "a boolean",
        })
        .map(Some)
}

fn required_topic(dict: &Dictionary, key: &str) -> Result<String> {
    let topic = required_string(dict, key)?;
    validate_topic(&topic)?;
    Ok(topic)
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_field(field, "must not be empty"));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "text field",
            actual: value.len(),
            limit: MAX_TEXT_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_field(field, "must not contain control characters"));
    }
    Ok(())
}

fn validate_declaration_identifier(value: &str) -> Result<String> {
    if value.is_empty() {
        return Err(invalid_field("Identifier", "must not be empty"));
    }
    if value.len() > MAX_DDM_IDENTIFIER_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "declaration identifier",
            actual: value.len(),
            limit: MAX_DDM_IDENTIFIER_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_field(
            "Identifier",
            "must not contain control characters",
        ));
    }
    Ok(value.to_owned())
}

fn validate_declaration_token(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_field("ServerToken", "must not be empty"));
    }
    if value.len() > MAX_DDM_IDENTIFIER_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "declaration server token",
            actual: value.len(),
            limit: MAX_DDM_IDENTIFIER_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_field(
            "ServerToken",
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_ddm_token(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_field(field, "must not be empty"));
    }
    if value.len() > MAX_DDM_TOKEN_BYTES {
        return Err(ProtocolError::InputTooLarge {
            kind: "declarative-management token",
            actual: value.len(),
            limit: MAX_DDM_TOKEN_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_field(field, "must not contain control characters"));
    }
    Ok(())
}

fn validate_ddm_timestamp(value: &str) -> Result<()> {
    validate_text("Timestamp", value)?;
    if value.len() > 64 {
        return Err(ProtocolError::InputTooLarge {
            kind: "declarative-management timestamp",
            actual: value.len(),
            limit: 64,
        });
    }
    Ok(())
}

fn validate_topic(topic: &str) -> Result<()> {
    validate_text("topic", topic)?;
    if !topic.starts_with("com.apple.mgmt.") {
        return Err(invalid_field("topic", "must start with `com.apple.mgmt.`"));
    }
    Ok(())
}

fn validate_public_url(url: &str) -> Result<String> {
    if url.is_empty() || url.len() > MAX_TEXT_BYTES {
        return Err(ProtocolError::InvalidEnrollmentProfile(
            "public_url must be a non-empty URL",
        ));
    }
    if !url.starts_with("https://") {
        return Err(ProtocolError::InvalidEnrollmentProfile(
            "public_url must use https",
        ));
    }
    let base = url.trim_end_matches('/');
    let host = base.strip_prefix("https://").unwrap_or_default();
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || host.contains('?')
        || host.contains('#')
    {
        return Err(ProtocolError::InvalidEnrollmentProfile(
            "public_url must contain a valid https authority",
        ));
    }
    Ok(base.to_owned())
}

fn validate_application_source(source: &ApplicationInstallSource) -> Result<()> {
    match source {
        ApplicationInstallSource::AppStore {
            itunes_store_id,
            purchase_method,
        } => {
            if *itunes_store_id == 0 {
                return Err(invalid_field(
                    "iTunesStoreID",
                    "must be a positive App Store identifier",
                ));
            }
            if *purchase_method != 1 {
                return Err(invalid_field(
                    "PurchaseMethod",
                    "only device-based licensing (1) is supported",
                ));
            }
        }
        ApplicationInstallSource::Enterprise { manifest_url } => {
            validate_manifest_url(manifest_url)?;
        }
    }
    Ok(())
}

fn validate_manifest_url(url: &str) -> Result<()> {
    validate_text("ManifestURL", url)?;
    if !url.starts_with("https://")
        || url
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_field(
            "ManifestURL",
            "must be an HTTPS URL without whitespace",
        ));
    }
    let authority = url.strip_prefix("https://").unwrap_or_default();
    if authority.is_empty() || authority.starts_with('/') {
        return Err(invalid_field(
            "ManifestURL",
            "must contain an HTTPS authority",
        ));
    }
    Ok(())
}

fn validate_identifier_list(field: &str, values: Option<&[String]>) -> Result<()> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.len() > MAX_QUERY_COUNT {
        return Err(ProtocolError::InputTooLarge {
            kind: "application identifier list",
            actual: values.len(),
            limit: MAX_QUERY_COUNT,
        });
    }
    for value in values {
        validate_text(field, value)?;
    }
    Ok(())
}

fn validate_pin(pin: &str) -> Result<()> {
    validate_text("PIN", pin)?;
    if pin.chars().count() != 6 {
        return Err(invalid_field("PIN", "must contain exactly six characters"));
    }
    Ok(())
}

fn validate_os_update(update: &OsUpdate) -> Result<()> {
    if update.product_key.is_none() && update.product_version.is_none() {
        return Err(invalid_field(
            "Updates",
            "each update needs ProductKey or ProductVersion",
        ));
    }
    if let Some(product_key) = &update.product_key {
        validate_text("ProductKey", product_key)?;
    }
    if let Some(product_version) = &update.product_version {
        validate_text("ProductVersion", product_version)?;
    }
    Ok(())
}

fn encode_os_update(update: &OsUpdate) -> Result<Dictionary> {
    let mut value = Dictionary::new();
    if let Some(product_key) = &update.product_key {
        value.insert("ProductKey".into(), Value::String(product_key.clone()));
    }
    if let Some(product_version) = &update.product_version {
        value.insert(
            "ProductVersion".into(),
            Value::String(product_version.clone()),
        );
    }
    value.insert(
        "InstallAction".into(),
        Value::String(os_install_action_string(update.install_action).into()),
    );
    if let Some(max_user_deferrals) = update.max_user_deferrals {
        value.insert(
            "MaxUserDeferrals".into(),
            Value::Integer(
                i64::try_from(max_user_deferrals)
                    .map_err(|_| invalid_field("MaxUserDeferrals", "must fit in a plist integer"))?
                    .into(),
            ),
        );
    }
    if let Some(priority) = update.priority {
        value.insert(
            "Priority".into(),
            Value::String(os_update_priority_string(priority).into()),
        );
    }
    Ok(value)
}

fn os_install_action_string(action: OsInstallAction) -> &'static str {
    match action {
        OsInstallAction::Default => "Default",
        OsInstallAction::DownloadOnly => "DownloadOnly",
        OsInstallAction::InstallAsap => "InstallASAP",
        OsInstallAction::NotifyOnly => "NotifyOnly",
        OsInstallAction::InstallLater => "InstallLater",
        OsInstallAction::InstallForceRestart => "InstallForceRestart",
    }
}

fn os_update_priority_string(priority: OsUpdatePriority) -> &'static str {
    match priority {
        OsUpdatePriority::Low => "Low",
        OsUpdatePriority::High => "High",
    }
}

fn obliteration_behavior_string(behavior: ObliterationBehavior) -> &'static str {
    match behavior {
        ObliterationBehavior::Default => "Default",
        ObliterationBehavior::DoNotObliterate => "DoNotObliterate",
        ObliterationBehavior::ObliterateWithWarning => "ObliterateWithWarning",
        ObliterationBehavior::Always => "Always",
    }
}

fn decode_pem_certificate(certificate: &[u8]) -> Result<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if !certificate.starts_with(BEGIN.as_bytes()) {
        return Ok(certificate.to_vec());
    }
    let text = std::str::from_utf8(certificate)
        .map_err(|error| ProtocolError::InvalidCertificate(error.to_string()))?;
    let body = text
        .strip_prefix(BEGIN)
        .and_then(|value| value.split_once(END))
        .filter(|(_, trailing)| trailing.trim().is_empty())
        .map(|(body, _)| body)
        .ok_or_else(|| ProtocolError::InvalidCertificate("invalid PEM envelope".into()))?;
    let encoded: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    STANDARD
        .decode(encoded)
        .map_err(|error| ProtocolError::InvalidCertificate(error.to_string()))
}

fn invalid_field(field: &str, reason: &str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

fn is_known_query(query: &str) -> bool {
    // This list is the stable, scalar portion of Apple's Device Information
    // schema. It intentionally excludes nested query namespaces and user data.
    const KNOWN_QUERIES: &[&str] = &[
        "UDID",
        "ProvisioningUDID",
        "OrganizationInfo",
        "MDMOptions",
        "LastCloudBackupDate",
        "AwaitingConfiguration",
        "iTunesStoreAccountIsActive",
        "iTunesStoreAccountHash",
        "DeviceName",
        "OSVersion",
        "SupplementalOSVersionExtra",
        "BuildVersion",
        "SupplementalBuildVersion",
        "ModelName",
        "Model",
        "ModelNumber",
        "IsAppleSilicon",
        "ProductName",
        "SerialNumber",
        "DeviceCapacity",
        "AvailableDeviceCapacity",
        "IMEI",
        "MEID",
        "ModemFirmwareVersion",
        "CellularTechnology",
        "BatteryLevel",
        "HasBattery",
        "IsSupervised",
        "IsMultiUser",
        "IsDeviceLocatorServiceEnabled",
        "IsActivationLockEnabled",
        "IsActivationLockSupported",
        "IsDoNotDisturbInEffect",
        "DeviceID",
        "EASDeviceIdentifier",
        "IsCloudBackupEnabled",
        "ActiveManagedUsers",
        "OSUpdateSettings",
        "LocalHostName",
        "HostName",
        "AutoSetupAdminAccounts",
        "SystemIntegrityProtectionEnabled",
        "SupportsLOMDevice",
        "IsMDMLostModeEnabled",
        "MaximumResidentUsers",
        "EstimatedResidentUsers",
        "QuotaSize",
        "ResidentUsers",
        "UserSessionTimeout",
        "TemporarySessionTimeout",
        "TemporarySessionOnly",
        "ManagedAppleIDDefaultDomains",
        "OnlineAuthenticationGracePeriod",
        "SkipLanguageAndLocaleSetupForNewUsers",
        "PushToken",
        "DiagnosticSubmissionEnabled",
        "AppAnalyticsEnabled",
        "TimeZone",
        "ICCID",
        "BluetoothMAC",
        "WiFiMAC",
        "EthernetMAC",
        "CurrentCarrierNetwork",
        "SIMCarrierNetwork",
        "SubscriberCarrierNetwork",
        "CarrierSettingsVersion",
        "PhoneNumber",
        "DataRoamingEnabled",
        "VoiceRoamingEnabled",
        "PersonalHotspotEnabled",
        "IsNetworkTethered",
        "IsRoaming",
        "SIMMCC",
        "SIMMNC",
        "SubscriberMCC",
        "SubscriberMNC",
        "CurrentMCC",
        "CurrentMNC",
        "ServiceSubscriptions",
        "PINRequiredForEraseDevice",
        "PINRequiredForDeviceLock",
        "SupportsiOSAppInstalls",
        "SoftwareUpdateDeviceID",
        "SoftwareUpdateSettings",
        "AccessibilitySettings",
        "DevicePropertiesAttestation",
        "EACSPreflight",
        "OrganizationName",
        "OrganizationAddress",
        "OrganizationPhone",
        "OrganizationEmail",
        "OrganizationMagic",
        "ActivationLockAllowedWhileSupervised",
        "BootstrapTokenAllowed",
        "PromptUserToAllowBootstrapTokenForAuthentication",
    ];
    KNOWN_QUERIES.contains(&query)
}

fn is_known_installed_application_item(item: &str) -> bool {
    const ITEMS: &[&str] = &[
        "AdHocCodeSigned",
        "AppStoreVendable",
        "BetaApp",
        "BundleSize",
        "DeviceBasedVPP",
        "DistributorIdentifier",
        "DynamicSize",
        "ExternalVersionIdentifier",
        "HasUpdateAvailable",
        "Identifier",
        "Installing",
        "IsAppClip",
        "IsValidated",
        "Name",
        "ShortVersion",
        "Version",
    ];
    ITEMS.contains(&item)
}
