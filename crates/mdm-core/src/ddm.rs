//! A deliberately small, protocol-independent Apple DDM declaration model.
//!
//! The wire shape follows Apple's declaration base: `Type`, `Identifier`,
//! `ServerToken`, and `Payload`.  This module validates the small set of
//! iPadOS device-channel declarations that this release advertises.  The
//! selected app-managed declaration covers App Store and HTTPS manifest targets
//! with the minimal install/license subset needed by this engine. It does not implement
//! the DDM check-in/status transport or claim support for declaration types
//! outside that set.

use crate::{OperationKind, Result, SupervisionEvidence, TransitionError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    str::FromStr,
};

const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_SERVER_TOKEN_BYTES: usize = 64;

/// The supported Apple declaration type strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppleDeclarationType {
    #[serde(rename = "com.apple.activation.simple")]
    ActivationSimple,
    #[serde(rename = "com.apple.configuration.app.managed")]
    AppManaged,
    #[serde(rename = "com.apple.configuration.management.status-subscriptions")]
    ManagementStatusSubscriptions,
    #[serde(rename = "com.apple.management.server-capabilities")]
    ManagementServerCapabilities,
}

/// Short aliases for callers that use the DDM terminology.
pub type DdmDeclarationType = AppleDeclarationType;
pub type DeclarationType = AppleDeclarationType;

impl AppleDeclarationType {
    /// The exact value required by Apple's DDM JSON wire format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivationSimple => "com.apple.activation.simple",
            Self::AppManaged => "com.apple.configuration.app.managed",
            Self::ManagementStatusSubscriptions => {
                "com.apple.configuration.management.status-subscriptions"
            }
            Self::ManagementServerCapabilities => "com.apple.management.server-capabilities",
        }
    }

    /// The declaration category used by DDM protocol endpoints.
    pub const fn category(self) -> &'static str {
        match self {
            Self::ActivationSimple => "activation",
            Self::AppManaged => "configuration",
            Self::ManagementStatusSubscriptions => "configuration",
            Self::ManagementServerCapabilities => "management",
        }
    }

    /// The first iPadOS version for which Apple's schema documents this type.
    ///
    /// The schema is shared by several enrollment modes.  This is therefore
    /// deliberately separate from [`Self::device_channel_minimum_ipados`],
    /// which is the service boundary used by this crate's iPadOS device
    /// target.
    pub const fn schema_minimum_ipados(self) -> OsVersion {
        match self {
            // DDM itself was introduced in iPadOS 15.0. AppManaged was
            // introduced later in the Apple declaration schema.
            Self::AppManaged => OsVersion::new(17, 2, 0),
            Self::ActivationSimple
            | Self::ManagementStatusSubscriptions
            | Self::ManagementServerCapabilities => OsVersion::new(15, 0, 0),
        }
    }

    /// The minimum iPadOS version accepted for this engine's device target.
    ///
    /// This service only claims profile-enrolled iPadOS device-channel
    /// support from iPadOS 16.  Apple introduced the declaration schemas in
    /// iPadOS 15, but device-enrollment support depends on the enrollment
    /// flow and is kept at the conservative runtime boundary here.
    pub const fn device_channel_minimum_ipados(self) -> OsVersion {
        match self {
            Self::AppManaged => OsVersion::new(17, 2, 0),
            Self::ActivationSimple
            | Self::ManagementStatusSubscriptions
            | Self::ManagementServerCapabilities => OsVersion::new(16, 0, 0),
        }
    }

    /// Alias for the minimum version accepted by the selected device target.
    pub const fn minimum_ipados(self) -> OsVersion {
        self.device_channel_minimum_ipados()
    }

    /// Parse one of the selected official declaration type strings.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "com.apple.activation.simple" => Ok(Self::ActivationSimple),
            "com.apple.configuration.app.managed" => Ok(Self::AppManaged),
            "com.apple.configuration.management.status-subscriptions" => {
                Ok(Self::ManagementStatusSubscriptions)
            }
            "com.apple.management.server-capabilities" => Ok(Self::ManagementServerCapabilities),
            other => Err(TransitionError::InvalidDdmDeclaration(format!(
                "unsupported declaration type {other:?}"
            ))),
        }
    }
}

impl fmt::Display for AppleDeclarationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AppleDeclarationType {
    type Err = TransitionError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

/// An Apple platform supported by this DDM boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DdmPlatform {
    #[serde(rename = "iPadOS")]
    IPadOS,
}

/// A DDM channel supported by this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdmChannel {
    Device,
}

/// A parsed Apple operating-system version used for support checks.
///
/// Server tokens are intentionally not represented by this type.  OS versions
/// are ordered for capability checks; declaration `ServerToken` values are
/// opaque strings and are compared only for exact equality.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct OsVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl OsVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let original = value;
        if value.is_empty() || value.trim() != value {
            return Err(TransitionError::InvalidDdmOsVersion(original.to_owned()));
        }
        let parts: Vec<&str> = value.split('.').collect();
        if !(1..=3).contains(&parts.len()) || parts.iter().any(|part| part.is_empty()) {
            return Err(TransitionError::InvalidDdmOsVersion(original.to_owned()));
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parts.iter().enumerate() {
            if !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TransitionError::InvalidDdmOsVersion(original.to_owned()));
            }
            numbers[index] = part
                .parse()
                .map_err(|_| TransitionError::InvalidDdmOsVersion(original.to_owned()))?;
        }
        Ok(Self::new(numbers[0], numbers[1], numbers[2]))
    }
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for OsVersion {
    type Err = TransitionError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for OsVersion {
    type Error = TransitionError;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<String> for OsVersion {
    type Error = TransitionError;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

/// Inputs accepted by [`AppleDeclaration::validate_for_ipados`].
pub trait OsVersionInput {
    fn into_os_version(self) -> Result<OsVersion>;
}

impl OsVersionInput for OsVersion {
    fn into_os_version(self) -> Result<OsVersion> {
        Ok(self)
    }
}

impl OsVersionInput for &OsVersion {
    fn into_os_version(self) -> Result<OsVersion> {
        Ok(*self)
    }
}

impl OsVersionInput for &str {
    fn into_os_version(self) -> Result<OsVersion> {
        OsVersion::parse(self)
    }
}

impl OsVersionInput for String {
    fn into_os_version(self) -> Result<OsVersion> {
        OsVersion::parse(&self)
    }
}

impl OsVersionInput for &String {
    fn into_os_version(self) -> Result<OsVersion> {
        OsVersion::parse(self)
    }
}

/// A concrete platform/channel/version target for a declaration check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DdmTarget {
    pub platform: DdmPlatform,
    pub channel: DdmChannel,
    pub os_version: OsVersion,
}

impl DdmTarget {
    pub const fn ipados_device(os_version: OsVersion) -> Self {
        Self {
            platform: DdmPlatform::IPadOS,
            channel: DdmChannel::Device,
            os_version,
        }
    }
}

/// Ownership policy for settings that could otherwise overlap with a
/// traditional MDM configuration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOwnership {
    /// No profile settings are claimed by this selected DDM declaration.
    Unclaimed,
    /// A traditional MDM profile owns the setting.
    TraditionalMdm,
    /// A DDM declaration owns the setting after an explicit bridge/hand-off.
    DeclarativeManagement,
}

/// Conflict policy for the selected declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileConflictPolicy {
    /// The selected declaration does not take control of a traditional MDM
    /// profile. The traditional profile remains the owner of its settings.
    TraditionalProfileUnaffected,
    /// Reserved for a future declaration that explicitly bridges a matching
    /// legacy profile. It is not returned by the current supported types.
    RequiresMatchingLegacyProfile,
}

/// Payload for `com.apple.activation.simple`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationSimplePayload {
    #[serde(rename = "StandardConfigurations")]
    pub standard_configurations: Vec<String>,
    #[serde(rename = "Predicate", default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

/// The install behavior subset supported for an iPadOS `AppManaged`
/// declaration.  The full Apple schema has additional macOS-only keys; this
/// boundary intentionally keeps only the device-channel iPadOS fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManagedInstallBehavior {
    #[serde(rename = "Install", default, skip_serializing_if = "Option::is_none")]
    pub install: Option<AppManagedInstallMode>,
    #[serde(rename = "License", default, skip_serializing_if = "Option::is_none")]
    pub license: Option<AppManagedLicense>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppManagedInstallMode {
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManagedLicense {
    #[serde(
        rename = "Assignment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignment: Option<AppManagedLicenseAssignment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppManagedLicenseAssignment {
    Device,
    User,
}

/// Payload subset for `com.apple.configuration.app.managed` on iPadOS.
///
/// iPadOS supports an App Store app identified by `AppStoreID` or `BundleID`,
/// and an enterprise app identified by `ManifestURL`. Exactly one source is
/// required. Composed identifiers and newer app-configuration fields are
/// outside this deliberately small iPadOS device-channel boundary. A license
/// assignment is required for App Store targets, as required by Apple's
/// schema guidance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppManagedPayload {
    #[serde(
        rename = "AppStoreID",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub app_store_id: Option<String>,
    #[serde(rename = "BundleID", default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(
        rename = "ManifestURL",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub manifest_url: Option<String>,
    #[serde(
        rename = "InstallBehavior",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub install_behavior: Option<AppManagedInstallBehavior>,
}

impl AppManagedPayload {
    /// Whether this declaration asks the device to install without waiting
    /// for user approval. Unsupervised iPadOS devices may prompt instead, so
    /// callers should use this flag to select the `SilentAppInstall` policy.
    pub fn is_silent_install(&self) -> bool {
        self.install_behavior
            .as_ref()
            .and_then(|behavior| behavior.install)
            == Some(AppManagedInstallMode::Required)
    }

    /// The operation policy represented by this payload.
    pub fn operation_kind(&self) -> OperationKind {
        if self.is_silent_install() {
            OperationKind::SilentAppInstall
        } else {
            OperationKind::DeclarativeManagement
        }
    }

    pub fn required_supervision(&self) -> bool {
        self.operation_kind().required_supervision()
    }

    pub fn check_supervision(&self, evidence: SupervisionEvidence) -> Result<()> {
        self.operation_kind().check_supervision(evidence)
    }
}

/// Status item names that this engine may request in a status subscription.
///
/// Apple's declaration schema intentionally leaves `StatusItems[].Name` as a
/// string because Apple can add status items independently of the declaration
/// schema.  The engine nevertheless keeps an explicit allowlist for the
/// subscription declarations it claims to support.  Status reports received
/// from a device are handled by the protocol crate and remain forward-
/// compatible with unknown names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StatusItemName {
    #[serde(rename = "app.managed.list")]
    AppManagedList,
    #[serde(rename = "device.identifier.serial-number")]
    DeviceIdentifierSerialNumber,
    #[serde(rename = "device.identifier.udid")]
    DeviceIdentifierUdid,
    #[serde(rename = "device.model.family")]
    DeviceModelFamily,
    #[serde(rename = "device.model.identifier")]
    DeviceModelIdentifier,
    #[serde(rename = "device.model.marketing-name")]
    DeviceModelMarketingName,
    #[serde(rename = "device.model.number")]
    DeviceModelNumber,
    #[serde(rename = "device.operating-system.build-version")]
    DeviceOperatingSystemBuildVersion,
    #[serde(rename = "device.operating-system.family")]
    DeviceOperatingSystemFamily,
    #[serde(rename = "device.operating-system.marketing-name")]
    DeviceOperatingSystemMarketingName,
    #[serde(rename = "device.operating-system.version")]
    DeviceOperatingSystemVersion,
    #[serde(rename = "management.client-capabilities")]
    ManagementClientCapabilities,
    #[serde(rename = "management.declarations")]
    ManagementDeclarations,
}

/// Compatibility names for callers that use the DDM terminology.
pub type KnownStatusItem = StatusItemName;
pub type DdmStatusItem = StatusItemName;

impl StatusItemName {
    /// All status items currently accepted in subscription declarations.
    pub const fn all() -> &'static [Self] {
        &[
            Self::AppManagedList,
            Self::DeviceIdentifierSerialNumber,
            Self::DeviceIdentifierUdid,
            Self::DeviceModelFamily,
            Self::DeviceModelIdentifier,
            Self::DeviceModelMarketingName,
            Self::DeviceModelNumber,
            Self::DeviceOperatingSystemBuildVersion,
            Self::DeviceOperatingSystemFamily,
            Self::DeviceOperatingSystemMarketingName,
            Self::DeviceOperatingSystemVersion,
            Self::ManagementClientCapabilities,
            Self::ManagementDeclarations,
        ]
    }

    /// The exact Apple status-item name used in a subscription declaration.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppManagedList => "app.managed.list",
            Self::DeviceIdentifierSerialNumber => "device.identifier.serial-number",
            Self::DeviceIdentifierUdid => "device.identifier.udid",
            Self::DeviceModelFamily => "device.model.family",
            Self::DeviceModelIdentifier => "device.model.identifier",
            Self::DeviceModelMarketingName => "device.model.marketing-name",
            Self::DeviceModelNumber => "device.model.number",
            Self::DeviceOperatingSystemBuildVersion => "device.operating-system.build-version",
            Self::DeviceOperatingSystemFamily => "device.operating-system.family",
            Self::DeviceOperatingSystemMarketingName => "device.operating-system.marketing-name",
            Self::DeviceOperatingSystemVersion => "device.operating-system.version",
            Self::ManagementClientCapabilities => "management.client-capabilities",
            Self::ManagementDeclarations => "management.declarations",
        }
    }

    /// Parse one status item from the engine's supported allowlist.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "app.managed.list" => Self::AppManagedList,
            "device.identifier.serial-number" => Self::DeviceIdentifierSerialNumber,
            "device.identifier.udid" => Self::DeviceIdentifierUdid,
            "device.model.family" => Self::DeviceModelFamily,
            "device.model.identifier" => Self::DeviceModelIdentifier,
            "device.model.marketing-name" => Self::DeviceModelMarketingName,
            "device.model.number" => Self::DeviceModelNumber,
            "device.operating-system.build-version" => Self::DeviceOperatingSystemBuildVersion,
            "device.operating-system.family" => Self::DeviceOperatingSystemFamily,
            "device.operating-system.marketing-name" => Self::DeviceOperatingSystemMarketingName,
            "device.operating-system.version" => Self::DeviceOperatingSystemVersion,
            "management.client-capabilities" => Self::ManagementClientCapabilities,
            "management.declarations" => Self::ManagementDeclarations,
            _ => return None,
        })
    }

    /// Whether a status item is in the subscription allowlist.
    pub fn is_supported(value: &str) -> bool {
        Self::parse(value).is_some()
    }

    /// The first iPadOS version in Apple's status-item schema.
    pub const fn schema_minimum_ipados(self) -> OsVersion {
        match self {
            Self::AppManagedList => OsVersion::new(17, 2, 0),
            Self::DeviceIdentifierSerialNumber | Self::DeviceIdentifierUdid => {
                OsVersion::new(16, 0, 0)
            }
            Self::DeviceModelNumber => OsVersion::new(17, 0, 0),
            Self::DeviceModelFamily
            | Self::DeviceModelIdentifier
            | Self::DeviceModelMarketingName
            | Self::DeviceOperatingSystemBuildVersion
            | Self::DeviceOperatingSystemFamily
            | Self::DeviceOperatingSystemMarketingName
            | Self::DeviceOperatingSystemVersion
            | Self::ManagementClientCapabilities
            | Self::ManagementDeclarations => OsVersion::new(15, 0, 0),
        }
    }

    /// The minimum version accepted by the engine's iPadOS device target.
    pub const fn minimum_ipados(self) -> OsVersion {
        self.schema_minimum_ipados()
    }
}

impl fmt::Display for StatusItemName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StatusItemName {
    type Err = TransitionError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value).ok_or_else(|| {
            invalid_payload(format!(
                "unsupported status subscription item name {value:?}"
            ))
        })
    }
}

/// One item in a status subscription declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSubscriptionItem {
    #[serde(rename = "Name")]
    pub name: String,
}

impl StatusSubscriptionItem {
    /// Construct one item from the engine's supported status-item allowlist.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let item = Self { name: name.into() };
        item.validate()?;
        Ok(item)
    }

    /// Resolve the item to a status schema known by this engine.
    pub fn supported_name(&self) -> Result<StatusItemName> {
        StatusItemName::parse(&self.name).ok_or_else(|| {
            invalid_payload(format!(
                "unsupported status subscription item name {:?}",
                self.name
            ))
        })
    }

    /// Validate the item name without requiring a complete declaration.
    pub fn validate(&self) -> Result<()> {
        self.supported_name().map(|_| ())
    }
}

/// Payload for `com.apple.configuration.management.status-subscriptions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementStatusSubscriptionsPayload {
    #[serde(rename = "StatusItems")]
    pub status_items: Vec<StatusSubscriptionItem>,
}

/// Payload for `com.apple.management.server-capabilities`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagementServerCapabilitiesPayload {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "SupportedFeatures")]
    pub supported_features: BTreeMap<String, Value>,
}

/// Typed payloads supported by this DDM boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AppleDeclarationPayload {
    ActivationSimple(ActivationSimplePayload),
    AppManaged(AppManagedPayload),
    ManagementStatusSubscriptions(ManagementStatusSubscriptionsPayload),
    ManagementServerCapabilities(ManagementServerCapabilitiesPayload),
}

pub type DdmPayload = AppleDeclarationPayload;

impl AppleDeclarationPayload {
    pub const fn declaration_type(&self) -> AppleDeclarationType {
        match self {
            Self::ActivationSimple(_) => AppleDeclarationType::ActivationSimple,
            Self::AppManaged(_) => AppleDeclarationType::AppManaged,
            Self::ManagementStatusSubscriptions(_) => {
                AppleDeclarationType::ManagementStatusSubscriptions
            }
            Self::ManagementServerCapabilities(_) => {
                AppleDeclarationType::ManagementServerCapabilities
            }
        }
    }

    pub fn into_value(self) -> Result<Value> {
        let value = match self {
            Self::ActivationSimple(payload) => serde_json::to_value(payload),
            Self::AppManaged(payload) => serde_json::to_value(payload),
            Self::ManagementStatusSubscriptions(payload) => serde_json::to_value(payload),
            Self::ManagementServerCapabilities(payload) => serde_json::to_value(payload),
        };
        value.map_err(|error| {
            TransitionError::InvalidDdmDeclaration(format!("payload serialization failed: {error}"))
        })
    }
}

/// A supported Apple DDM declaration in its wire-compatible JSON shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleDeclaration {
    #[serde(rename = "Type")]
    pub declaration_type: String,
    #[serde(rename = "Identifier")]
    pub identifier: String,
    #[serde(rename = "ServerToken")]
    pub server_token: String,
    #[serde(rename = "Payload")]
    pub payload: Value,
}

pub type DdmDeclaration = AppleDeclaration;

impl AppleDeclaration {
    /// Construct and validate one supported declaration.
    pub fn new(
        declaration_type: impl Into<String>,
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: Value,
    ) -> Result<Self> {
        let declaration = Self {
            declaration_type: declaration_type.into(),
            identifier: identifier.into(),
            server_token: server_token.into(),
            payload,
        };
        declaration.validate()?;
        Ok(declaration)
    }

    /// Construct from one of the typed payloads supported by this module.
    pub fn from_payload(
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: AppleDeclarationPayload,
    ) -> Result<Self> {
        let declaration_type = payload.declaration_type().as_str();
        Self::new(
            declaration_type,
            identifier,
            server_token,
            payload.into_value()?,
        )
    }

    pub fn activation_simple(
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: ActivationSimplePayload,
    ) -> Result<Self> {
        Self::from_payload(
            identifier,
            server_token,
            AppleDeclarationPayload::ActivationSimple(payload),
        )
    }

    pub fn app_managed(
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: AppManagedPayload,
    ) -> Result<Self> {
        Self::from_payload(
            identifier,
            server_token,
            AppleDeclarationPayload::AppManaged(payload),
        )
    }

    pub fn management_status_subscriptions(
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: ManagementStatusSubscriptionsPayload,
    ) -> Result<Self> {
        Self::from_payload(
            identifier,
            server_token,
            AppleDeclarationPayload::ManagementStatusSubscriptions(payload),
        )
    }

    pub fn management_server_capabilities(
        identifier: impl Into<String>,
        server_token: impl Into<String>,
        payload: ManagementServerCapabilitiesPayload,
    ) -> Result<Self> {
        Self::from_payload(
            identifier,
            server_token,
            AppleDeclarationPayload::ManagementServerCapabilities(payload),
        )
    }

    /// Validate the declaration base and the selected payload schema.
    pub fn validate(&self) -> Result<()> {
        validate_text_field(&self.declaration_type, "Type", MAX_IDENTIFIER_BYTES)?;
        validate_text_field(&self.identifier, "Identifier", MAX_IDENTIFIER_BYTES)?;
        validate_text_field(&self.server_token, "ServerToken", MAX_SERVER_TOKEN_BYTES)?;
        if !self.payload.is_object() {
            return Err(invalid_payload("Payload must be a JSON object"));
        }
        let declaration_type = AppleDeclarationType::parse(&self.declaration_type)?;
        validate_payload(declaration_type, &self.payload)
    }

    /// Validate against the iPadOS device-channel support boundary.
    pub fn validate_for_ipados<V: OsVersionInput>(&self, os_version: V) -> Result<()> {
        let os_version = os_version.into_os_version()?;
        self.validate()?;
        let declaration_type = AppleDeclarationType::parse(&self.declaration_type)?;
        if os_version < declaration_type.minimum_ipados() {
            return Err(TransitionError::UnsupportedDdmTarget(format!(
                "{} requires iPadOS {}, got {}",
                declaration_type,
                declaration_type.minimum_ipados(),
                os_version
            )));
        }
        if declaration_type == AppleDeclarationType::ManagementStatusSubscriptions {
            validate_status_items_for_ipados(&self.payload, os_version)?;
        }
        Ok(())
    }

    /// Validate against a concrete platform/channel/version target.
    pub fn validate_for_target(&self, target: &DdmTarget) -> Result<()> {
        if target.platform != DdmPlatform::IPadOS || target.channel != DdmChannel::Device {
            return Err(TransitionError::UnsupportedDdmTarget(
                "only the iPadOS device channel is supported".to_owned(),
            ));
        }
        self.validate_for_ipados(target.os_version)
    }

    /// Return the declaration category (`activation`, `configuration`, or
    /// `management`). Unknown wire values are reported as `unknown`; call
    /// [`Self::validate`] to obtain a structured error.
    pub fn kind(&self) -> String {
        AppleDeclarationType::parse(&self.declaration_type)
            .map(AppleDeclarationType::category)
            .unwrap_or("unknown")
            .to_owned()
    }

    pub fn kind_str(&self) -> &'static str {
        AppleDeclarationType::parse(&self.declaration_type)
            .map(AppleDeclarationType::category)
            .unwrap_or("unknown")
    }

    pub fn category(&self) -> String {
        self.kind()
    }

    pub fn supported_type(&self) -> Result<AppleDeclarationType> {
        AppleDeclarationType::parse(&self.declaration_type)
    }

    pub fn minimum_ipados(&self) -> Result<OsVersion> {
        Ok(self.supported_type()?.minimum_ipados())
    }

    /// The selected declarations do not take ownership of settings from a
    /// traditional MDM profile. Profile migration requires a future explicit
    /// legacy-profile bridge and is outside this model.
    pub const fn profile_ownership(&self) -> ProfileOwnership {
        ProfileOwnership::Unclaimed
    }

    pub const fn profile_conflict_policy(&self) -> ProfileConflictPolicy {
        ProfileConflictPolicy::TraditionalProfileUnaffected
    }

    /// Canonicalize the payload recursively, sorting object keys while
    /// preserving array order and scalar values.
    pub fn canonical_payload(&self) -> Value {
        canonicalize(&self.payload)
    }

    /// Canonical content excludes the identifier and server revision token.
    /// Those values are compared separately as opaque identity metadata.
    pub fn canonical_content(&self) -> Value {
        let mut object = Map::new();
        object.insert("Payload".to_owned(), self.canonical_payload());
        object.insert(
            "Type".to_owned(),
            Value::String(self.declaration_type.clone()),
        );
        canonicalize(&Value::Object(object))
    }

    pub fn canonical_content_json(&self) -> String {
        serde_json::to_string(&self.canonical_content())
            .expect("serde_json::Value is always serializable")
    }

    /// Canonicalize the complete declaration, including identity metadata.
    pub fn canonical_json(&self) -> String {
        let mut object = Map::new();
        object.insert(
            "Identifier".to_owned(),
            Value::String(self.identifier.clone()),
        );
        object.insert("Payload".to_owned(), self.canonical_payload());
        object.insert(
            "ServerToken".to_owned(),
            Value::String(self.server_token.clone()),
        );
        object.insert(
            "Type".to_owned(),
            Value::String(self.declaration_type.clone()),
        );
        serde_json::to_string(&canonicalize(&Value::Object(object)))
            .expect("serde_json::Value is always serializable")
    }

    /// Whether the declaration's type and payload content are equal,
    /// independent of its identifier and opaque server token.
    pub fn content_equal(&self, other: &Self) -> bool {
        self.declaration_type == other.declaration_type
            && self.canonical_payload() == other.canonical_payload()
    }

    pub fn same_content(&self, other: &Self) -> bool {
        self.content_equal(other)
    }

    /// Whether both declarations identify the same exact opaque revision.
    pub fn same_revision(&self, other: &Self) -> bool {
        self.declaration_type == other.declaration_type
            && self.identifier == other.identifier
            && self.server_token == other.server_token
    }
}

fn invalid_payload(reason: impl Into<String>) -> TransitionError {
    TransitionError::InvalidDdmDeclaration(reason.into())
}

fn validate_text_field(value: &str, field: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_payload(format!("{field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(invalid_payload(format!(
            "{field} must be at most {max_bytes} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_payload(format!(
            "{field} contains a control character"
        )));
    }
    if field == "Identifier" && value.contains('/') {
        // The selected service exposes declaration identifiers in the
        // `/declaration/<category>/<identifier>` endpoint path.  Apple uses
        // opaque strings in the general schema, but this engine deliberately
        // restricts its supported identifiers to one path segment so an
        // identifier cannot be misrouted by the transport layer.
        return Err(invalid_payload(
            "Identifier must not contain '/' for this engine",
        ));
    }
    Ok(())
}

fn validate_payload(declaration_type: AppleDeclarationType, payload: &Value) -> Result<()> {
    let object = payload
        .as_object()
        .ok_or_else(|| invalid_payload("Payload must be a JSON object"))?;
    match declaration_type {
        AppleDeclarationType::ActivationSimple => validate_activation_simple(object),
        AppleDeclarationType::AppManaged => validate_app_managed(object),
        AppleDeclarationType::ManagementStatusSubscriptions => {
            validate_status_subscriptions(object)
        }
        AppleDeclarationType::ManagementServerCapabilities => validate_server_capabilities(object),
    }
}

fn ensure_allowed_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if let Some(key) = object
        .keys()
        .find(|key| !allowed.iter().any(|allowed_key| allowed_key == key))
    {
        return Err(invalid_payload(format!("unknown payload key {key:?}")));
    }
    Ok(())
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    let value = object
        .get(key)
        .ok_or_else(|| invalid_payload(format!("required payload key {key} is missing")))?;
    let value = value
        .as_str()
        .ok_or_else(|| invalid_payload(format!("payload key {key} must be a string")))?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_payload(format!(
            "payload key {key} must not be empty"
        )));
    }
    Ok(value)
}

fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid_payload(format!("payload key {key} must be a string")))?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid_payload(format!(
            "payload key {key} must not be empty"
        )));
    }
    Ok(Some(value))
}

fn validate_activation_simple(object: &Map<String, Value>) -> Result<()> {
    ensure_allowed_keys(object, &["StandardConfigurations", "Predicate"])?;
    let configurations = object
        .get("StandardConfigurations")
        .ok_or_else(|| invalid_payload("StandardConfigurations is required"))?
        .as_array()
        .ok_or_else(|| invalid_payload("StandardConfigurations must be an array"))?;
    if configurations.is_empty() {
        return Err(invalid_payload(
            "StandardConfigurations must contain at least one identifier",
        ));
    }
    let mut identifiers = HashSet::new();
    for value in configurations {
        let identifier = value
            .as_str()
            .ok_or_else(|| invalid_payload("StandardConfigurations items must be strings"))?;
        if identifier.trim().is_empty()
            || identifier.chars().any(char::is_control)
            || identifier.contains('/')
        {
            return Err(invalid_payload(
                "StandardConfigurations identifiers must be non-empty and must not contain '/'",
            ));
        }
        if !identifiers.insert(identifier) {
            return Err(invalid_payload(
                "StandardConfigurations must not contain duplicates",
            ));
        }
    }
    optional_string(object, "Predicate")?;
    Ok(())
}

fn validate_app_managed(object: &Map<String, Value>) -> Result<()> {
    ensure_allowed_keys(
        object,
        &["AppStoreID", "BundleID", "ManifestURL", "InstallBehavior"],
    )?;
    let app_store_id = optional_string(object, "AppStoreID")?;
    let bundle_id = optional_string(object, "BundleID")?;
    let manifest_url = optional_string(object, "ManifestURL")?;
    let source_count = [app_store_id, bundle_id, manifest_url]
        .into_iter()
        .flatten()
        .count();
    if source_count != 1 {
        return Err(invalid_payload(
            "AppManaged requires exactly one of AppStoreID, BundleID, or ManifestURL",
        ));
    }

    if let Some(app_store_id) = app_store_id
        && !app_store_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_payload("AppStoreID must contain only digits"));
    }
    if let Some(manifest_url) = manifest_url {
        validate_manifest_url(manifest_url)?;
    }

    let install_behavior = object.get("InstallBehavior");
    if let Some(value) = install_behavior {
        let behavior = value
            .as_object()
            .ok_or_else(|| invalid_payload("InstallBehavior must be an object"))?;
        ensure_allowed_keys(behavior, &["Install", "License"])?;
        if let Some(install) = behavior.get("Install") {
            let install = install
                .as_str()
                .ok_or_else(|| invalid_payload("InstallBehavior.Install must be a string"))?;
            if !matches!(install, "Optional" | "Required") {
                return Err(invalid_payload(
                    "InstallBehavior.Install must be Optional or Required",
                ));
            }
        }
        if let Some(license) = behavior.get("License") {
            let license = license
                .as_object()
                .ok_or_else(|| invalid_payload("InstallBehavior.License must be an object"))?;
            ensure_allowed_keys(license, &["Assignment"])?;
            let assignment = required_string(license, "Assignment")?;
            if !matches!(assignment, "Device" | "User") {
                return Err(invalid_payload(
                    "InstallBehavior.License.Assignment must be Device or User",
                ));
            }
        }
    }

    // AppStoreID and BundleID select App Store apps in the iPadOS schema.
    // Apple requires an explicit device/user license assignment for those
    // apps to install or update. Enterprise manifest apps do not require one.
    let has_assignment = install_behavior
        .and_then(Value::as_object)
        .and_then(|behavior| behavior.get("License"))
        .and_then(Value::as_object)
        .and_then(|license| license.get("Assignment"))
        .is_some();
    if (app_store_id.is_some() || bundle_id.is_some()) && !has_assignment {
        return Err(invalid_payload(
            "AppManaged App Store targets require InstallBehavior.License.Assignment",
        ));
    }
    Ok(())
}

fn validate_manifest_url(url: &str) -> Result<()> {
    if !url.starts_with("https://")
        || url
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid_payload(
            "ManifestURL must be an HTTPS URL without whitespace",
        ));
    }
    let authority = url.strip_prefix("https://").unwrap_or_default();
    if authority.is_empty() || authority.starts_with('/') {
        return Err(invalid_payload(
            "ManifestURL must contain an HTTPS authority",
        ));
    }
    Ok(())
}

fn validate_status_subscriptions(object: &Map<String, Value>) -> Result<()> {
    ensure_allowed_keys(object, &["StatusItems"])?;
    let status_items = object
        .get("StatusItems")
        .ok_or_else(|| invalid_payload("StatusItems is required"))?
        .as_array()
        .ok_or_else(|| invalid_payload("StatusItems must be an array"))?;
    if status_items.is_empty() {
        return Err(invalid_payload(
            "StatusItems must contain at least one item",
        ));
    }
    let mut names = HashSet::new();
    for item in status_items {
        let item = item
            .as_object()
            .ok_or_else(|| invalid_payload("StatusItems items must be objects"))?;
        ensure_allowed_keys(item, &["Name"])?;
        let name = required_string(item, "Name")?;
        StatusItemName::parse(name).ok_or_else(|| {
            invalid_payload(format!(
                "unsupported status subscription item name {name:?}"
            ))
        })?;
        if !names.insert(name) {
            return Err(invalid_payload(
                "StatusItems must not contain duplicate names",
            ));
        }
    }
    Ok(())
}

fn validate_status_items_for_ipados(payload: &Value, os_version: OsVersion) -> Result<()> {
    let items = payload
        .get("StatusItems")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_payload("StatusItems must be an array"))?;
    for item in items {
        let name = item
            .get("Name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_payload("StatusItems items must contain a Name string"))?;
        let status_item = StatusItemName::parse(name).ok_or_else(|| {
            invalid_payload(format!(
                "unsupported status subscription item name {name:?}"
            ))
        })?;
        let minimum = status_item.minimum_ipados();
        if os_version < minimum {
            return Err(TransitionError::UnsupportedDdmTarget(format!(
                "status item {} requires iPadOS {}, got {}",
                status_item, minimum, os_version
            )));
        }
    }
    Ok(())
}

fn validate_server_capabilities(object: &Map<String, Value>) -> Result<()> {
    ensure_allowed_keys(object, &["Version", "SupportedFeatures"])?;
    required_string(object, "Version")?;
    object
        .get("SupportedFeatures")
        .ok_or_else(|| invalid_payload("SupportedFeatures is required"))?
        .as_object()
        .ok_or_else(|| invalid_payload("SupportedFeatures must be an object"))?;
    Ok(())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize(&object[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn activation(identifier: &str, token: &str, payload: Value) -> AppleDeclaration {
        AppleDeclaration::new("com.apple.activation.simple", identifier, token, payload).unwrap()
    }

    #[test]
    fn validates_common_wire_shape_and_opaque_tokens() {
        let declaration = activation(
            "id",
            "v1.0",
            json!({"StandardConfigurations": ["config-a"]}),
        );
        assert_eq!(declaration.kind(), "activation");
        assert_eq!(declaration.server_token, "v1.0");
        assert!(AppleDeclaration::new("com.apple.unknown", "id", "token", json!({})).is_err());
        assert!(
            AppleDeclaration::new(
                "com.apple.activation.simple",
                "",
                "token",
                json!({"StandardConfigurations": ["config-a"]})
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.activation.simple",
                "id",
                "",
                json!({"StandardConfigurations": ["config-a"]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<AppleDeclaration>(json!({
                "Type": "com.apple.activation.simple",
                "Identifier": "id",
                "ServerToken": "token",
                "Payload": {"StandardConfigurations": ["config-a"]},
                "Unexpected": true
            }))
            .is_err()
        );
    }

    #[test]
    fn validates_selected_official_payload_shapes() {
        assert!(
            activation(
                "activation",
                "opaque-token",
                json!({
                    "StandardConfigurations": ["configuration-a", "configuration-b"],
                    "Predicate": "(@status(device.model.family) == 'iPad')"
                }),
            )
            .validate_for_ipados("16.0")
            .is_ok()
        );

        let status = AppleDeclaration::new(
            "com.apple.configuration.management.status-subscriptions",
            "status",
            "one",
            json!({"StatusItems": [{"Name": "device.model.family"}]}),
        )
        .unwrap();
        assert_eq!(status.kind(), "configuration");
        assert!(status.validate_for_ipados("16.0").is_ok());

        let server = AppleDeclaration::new(
            "com.apple.management.server-capabilities",
            "server",
            "one",
            json!({
                "Version": "1.0",
                "SupportedFeatures": {
                    "com.apple.example.feature": {"parameter": true},
                    "vendor.example.feature": ["opaque", 1]
                }
            }),
        )
        .unwrap();
        assert_eq!(server.kind(), "management");
        assert!(server.validate_for_ipados("16.0").is_ok());
        assert!(
            AppleDeclaration::new(
                "com.apple.management.server-capabilities",
                "bad-features",
                "one",
                json!({"Version": "1.0", "SupportedFeatures": []}),
            )
            .is_err()
        );

        assert!(
            AppleDeclaration::new(
                "com.apple.configuration.management.status-subscriptions",
                "bad",
                "token",
                json!({"StatusItems": []})
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.management.server-capabilities",
                "bad",
                "token",
                json!({"Version": "1.0"})
            )
            .is_err()
        );
    }

    #[test]
    fn target_os_support_is_explicitly_limited_to_ipados_device_channel() {
        let declaration = activation(
            "activation",
            "token",
            json!({"StandardConfigurations": ["configuration-a"]}),
        );
        assert!(declaration.validate_for_ipados("15.0").is_err());
        assert!(declaration.validate_for_ipados("16.0").is_ok());
        assert!(declaration.validate_for_ipados("14.9").is_err());
        assert!(
            declaration
                .validate_for_target(&DdmTarget::ipados_device(OsVersion::new(17, 0, 0)))
                .is_ok()
        );
        assert_eq!(declaration.profile_ownership(), ProfileOwnership::Unclaimed);
        assert_eq!(
            declaration.profile_conflict_policy(),
            ProfileConflictPolicy::TraditionalProfileUnaffected
        );
    }

    #[test]
    fn canonical_content_ignores_json_object_order_but_not_array_order() {
        let first = activation(
            "same-id",
            "opaque",
            json!({
                "Predicate": "true",
                "StandardConfigurations": ["a", "b"]
            }),
        );
        let reordered = activation(
            "same-id",
            "opaque",
            json!({
                "StandardConfigurations": ["a", "b"],
                "Predicate": "true"
            }),
        );
        let array_reordered = activation(
            "same-id",
            "opaque",
            json!({
                "StandardConfigurations": ["b", "a"],
                "Predicate": "true"
            }),
        );
        assert!(first.content_equal(&reordered));
        assert_eq!(
            first.canonical_content_json(),
            reordered.canonical_content_json()
        );
        assert!(!first.content_equal(&array_reordered));
        assert!(first.same_revision(&reordered));
        assert!(first.canonical_json().contains("ServerToken"));
    }

    #[test]
    fn typed_payload_constructors_match_wire_types() {
        let declaration = AppleDeclaration::from_payload(
            "status",
            "token",
            AppleDeclarationPayload::ManagementStatusSubscriptions(
                ManagementStatusSubscriptionsPayload {
                    status_items: vec![StatusSubscriptionItem {
                        name: "device.model.family".to_owned(),
                    }],
                },
            ),
        )
        .unwrap();
        assert_eq!(
            declaration.declaration_type,
            "com.apple.configuration.management.status-subscriptions"
        );
        assert!(declaration.validate().is_ok());
    }

    #[test]
    fn app_managed_is_limited_to_the_supported_ipados_subset() {
        let declaration = AppleDeclaration::app_managed(
            "managed-app",
            "token",
            AppManagedPayload {
                app_store_id: Some("123456789".to_owned()),
                bundle_id: None,
                manifest_url: None,
                install_behavior: Some(AppManagedInstallBehavior {
                    install: Some(AppManagedInstallMode::Required),
                    license: Some(AppManagedLicense {
                        assignment: Some(AppManagedLicenseAssignment::Device),
                    }),
                }),
            },
        )
        .unwrap();
        assert_eq!(declaration.kind(), "configuration");
        assert_eq!(
            declaration
                .payload
                .get("InstallBehavior")
                .and_then(|value| value.get("Install"))
                .and_then(Value::as_str),
            Some("Required")
        );
        assert!(declaration.validate_for_ipados("17.2").is_ok());
        assert!(declaration.validate_for_ipados("17.1").is_err());

        let enterprise = AppleDeclaration::app_managed(
            "managed-enterprise-app",
            "token",
            AppManagedPayload {
                app_store_id: None,
                bundle_id: None,
                manifest_url: Some("https://example.invalid/app-manifest.plist".to_owned()),
                install_behavior: Some(AppManagedInstallBehavior {
                    install: Some(AppManagedInstallMode::Required),
                    license: None,
                }),
            },
        )
        .unwrap();
        assert!(enterprise.validate_for_ipados("17.2").is_ok());

        assert!(
            AppleDeclaration::new(
                "com.apple.configuration.app.managed",
                "bad",
                "token",
                json!({"AppStoreID": "123"}),
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.configuration.app.managed",
                "bad-id",
                "token",
                json!({
                    "AppStoreID": "not-numeric",
                    "InstallBehavior": {"License": {"Assignment": "Device"}}
                }),
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.configuration.app.managed",
                "bad-manifest",
                "token",
                json!({"ManifestURL": "http://example.invalid/app.plist"}),
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.configuration.app.managed",
                "bad",
                "token",
                json!({
                    "BundleID": "com.example.app",
                    "InstallBehavior": {
                        "Install": "Required",
                        "License": {"Assignment": "Device"}
                    },
                    "ManifestURL": "https://example.invalid/manifest.plist"
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn status_subscriptions_use_a_narrow_allowlist_and_os_gates() {
        let unknown = AppleDeclaration::new(
            "com.apple.configuration.management.status-subscriptions",
            "status",
            "token",
            json!({"StatusItems": [{"Name": "future.status.item"}]}),
        );
        assert!(unknown.is_err());

        let model_number = AppleDeclaration::new(
            "com.apple.configuration.management.status-subscriptions",
            "status-model-number",
            "token",
            json!({"StatusItems": [{"Name": "device.model.number"}]}),
        )
        .unwrap();
        assert!(model_number.validate_for_ipados("16.0").is_err());
        assert!(model_number.validate_for_ipados("17.0").is_ok());

        assert_eq!(
            StatusItemName::parse("device.identifier.udid"),
            Some(StatusItemName::DeviceIdentifierUdid)
        );
        assert_eq!(
            StatusItemName::DeviceIdentifierUdid.schema_minimum_ipados(),
            OsVersion::new(16, 0, 0)
        );
        let app_managed_status = AppleDeclaration::new(
            "com.apple.configuration.management.status-subscriptions",
            "status-app-managed",
            "token",
            json!({"StatusItems": [{"Name": "app.managed.list"}]}),
        )
        .unwrap();
        assert!(app_managed_status.validate_for_ipados("17.2").is_ok());
        assert!(app_managed_status.validate_for_ipados("17.1").is_err());
        assert!(StatusItemName::parse("future.status.item").is_none());
    }

    #[test]
    fn selected_engine_identifiers_are_single_path_segments() {
        assert!(
            AppleDeclaration::new(
                "com.apple.activation.simple",
                "activation/child",
                "token",
                json!({"StandardConfigurations": ["configuration-a"]}),
            )
            .is_err()
        );
        assert!(
            AppleDeclaration::new(
                "com.apple.activation.simple",
                "activation",
                "token",
                json!({"StandardConfigurations": ["configuration/a"]}),
            )
            .is_err()
        );
    }
}
