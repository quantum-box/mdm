//! Protocol-independent policies for device operations.
//!
//! The protocol crate owns Apple plist/XML encoding.  This module owns the
//! decision boundary that must be checked before a command is queued: whether
//! an operation is read-only, whether it needs supervision, and the small
//! value objects used by application, kiosk, and software-update workflows.

use crate::{CommandKind, Result, TransitionError};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

const MAX_BUNDLE_IDENTIFIER_BYTES: usize = 255;
const MAX_OPERATION_TEXT_BYTES: usize = 512;

/// A device operation independent of its wire representation.
///
/// The names intentionally follow Apple's command names where a command
/// exists.  `KioskMode` and `SilentAppInstall` are policy operations: the
/// protocol layer may realize them with a profile, an application command, or
/// a declarative declaration after this policy has admitted the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    DeviceInformation,
    InstalledApplicationList,
    ManagedApplicationList,
    AvailableOsUpdates,
    OsUpdateStatus,
    InstallApplication,
    RemoveApplication,
    SilentAppInstall,
    KioskMode,
    ScheduleOsUpdate,
    DeviceLock,
    EraseDevice,
    EnableLostMode,
    DisableLostMode,
    DeviceConfigured,
    AutomatedDeviceEnrollment,
    DeclarativeManagement,
    InstallProfile,
    RemoveProfile,
}

impl OperationKind {
    /// Compatibility spellings for callers that preserve Apple's acronym
    /// capitalization in Rust identifiers.
    #[allow(non_upper_case_globals)]
    pub const AvailableOSUpdates: Self = Self::AvailableOsUpdates;
    #[allow(non_upper_case_globals)]
    pub const OSUpdateStatus: Self = Self::OsUpdateStatus;
    #[allow(non_upper_case_globals)]
    pub const ScheduleOSUpdate: Self = Self::ScheduleOsUpdate;
    #[allow(non_upper_case_globals)]
    pub const SilentApplicationInstall: Self = Self::SilentAppInstall;
    #[allow(non_upper_case_globals)]
    pub const Kiosk: Self = Self::KioskMode;
    #[allow(non_upper_case_globals)]
    pub const DeviceWipe: Self = Self::EraseDevice;

    /// Whether Apple's iPadOS device-channel rules require supervision for
    /// this operation.  This is deliberately conservative for operations
    /// where a mistaken unsupervised request could silently fail or prompt a
    /// user instead of applying policy.
    pub const fn required_supervision(self) -> bool {
        matches!(
            self,
            Self::AvailableOsUpdates
                | Self::OsUpdateStatus
                | Self::SilentAppInstall
                | Self::KioskMode
                | Self::ScheduleOsUpdate
                | Self::EnableLostMode
                | Self::DisableLostMode
                | Self::DeviceConfigured
        )
    }

    /// Alias that reads naturally at call sites which use a boolean policy
    /// field named `requires_supervision`.
    pub const fn requires_supervision(self) -> bool {
        self.required_supervision()
    }

    /// Whether the operation has no intended device-side mutation and is safe
    /// to retry after a transport timeout.
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::DeviceInformation
                | Self::InstalledApplicationList
                | Self::ManagedApplicationList
                | Self::AvailableOsUpdates
                | Self::OsUpdateStatus
        )
    }

    /// Return the command timeout policy used by the core state machine.
    pub const fn retry_after_timeout(self) -> bool {
        self.is_read_only()
    }

    pub const fn timeout_is_ambiguous(self) -> bool {
        !self.is_read_only()
    }

    /// Build the supervision policy for this operation.
    pub const fn eligibility(self) -> OperationEligibility {
        OperationEligibility {
            operation: self,
            required_supervision: self.required_supervision(),
        }
    }

    /// Check the operation against device supervision evidence.
    pub fn check_supervision(self, evidence: SupervisionEvidence) -> Result<()> {
        self.eligibility().check(evidence)
    }
}

/// Evidence available to the service about a device's supervision state.
///
/// `Unknown` is intentionally distinct from `Unsupervised`.  Both values are
/// rejected for operations whose `required_supervision` flag is true.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionEvidence {
    Supervised,
    Unsupervised,
    #[default]
    Unknown,
}

/// Enrollment mode evidence retained alongside supervision evidence.
///
/// ADE is an enrollment mechanism, not a substitute for device-reported
/// supervision evidence.  Callers must still pass `SupervisionEvidence` to
/// [`OperationEligibility::check`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentMode {
    Manual,
    #[serde(rename = "automated_device_enrollment")]
    AutomatedDeviceEnrollment,
    UserEnrollment,
    #[default]
    Unknown,
}

impl EnrollmentMode {
    /// Compatibility spelling for code that uses Apple's ADE acronym.
    #[allow(non_upper_case_globals)]
    pub const Ade: Self = Self::AutomatedDeviceEnrollment;
    pub const ADE: Self = Self::AutomatedDeviceEnrollment;
}

/// The explicit operation policy the application layer should persist or
/// inspect before enqueuing a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationEligibility {
    pub operation: OperationKind,
    pub required_supervision: bool,
}

impl OperationEligibility {
    pub const fn for_operation(operation: OperationKind) -> Self {
        operation.eligibility()
    }

    pub const fn new(operation: OperationKind) -> Self {
        Self::for_operation(operation)
    }

    pub const fn requires_supervision(self) -> bool {
        self.required_supervision
    }

    /// Admit an operation only when the evidence satisfies its policy.
    pub fn check(self, evidence: SupervisionEvidence) -> Result<()> {
        if !self.required_supervision || evidence == SupervisionEvidence::Supervised {
            return Ok(());
        }
        Err(TransitionError::OperationRequiresSupervision {
            operation: self.operation,
            evidence,
        })
    }

    pub fn is_eligible(self, evidence: SupervisionEvidence) -> bool {
        self.check(evidence).is_ok()
    }
}

/// A compact device context for callers that need both enrollment and
/// supervision evidence in one value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceManagementContext {
    pub enrollment_mode: EnrollmentMode,
    pub supervision: SupervisionEvidence,
}

impl DeviceManagementContext {
    pub const fn new(enrollment_mode: EnrollmentMode, supervision: SupervisionEvidence) -> Self {
        Self {
            enrollment_mode,
            supervision,
        }
    }

    pub fn check(&self, operation: OperationKind) -> Result<()> {
        operation.check_supervision(self.supervision)
    }
}

/// A validated application bundle identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BundleIdentifier(String);

impl BundleIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_bundle_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for BundleIdentifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BundleIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for BundleIdentifier {
    type Error = TransitionError;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<&str> for BundleIdentifier {
    type Error = TransitionError;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

/// An application command policy before it is translated into an Apple
/// `InstallApplication` or `RemoveApplication` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppOperationKind {
    Install,
    Remove,
    Update,
    SilentInstall,
}

impl AppOperationKind {
    #[allow(non_upper_case_globals)]
    pub const SilentApplicationInstall: Self = Self::SilentInstall;

    pub const fn operation_kind(self) -> OperationKind {
        match self {
            Self::Install | Self::Update => OperationKind::InstallApplication,
            Self::Remove => OperationKind::RemoveApplication,
            Self::SilentInstall => OperationKind::SilentAppInstall,
        }
    }

    pub const fn command_kind(self) -> CommandKind {
        match self {
            Self::Install | Self::Update | Self::SilentInstall => CommandKind::InstallApplication,
            Self::Remove => CommandKind::RemoveApplication,
        }
    }

    pub const fn required_supervision(self) -> bool {
        self.operation_kind().required_supervision()
    }
}

/// An application install, update, or removal request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppOperationRequest {
    pub operation: AppOperationKind,
    pub bundle_identifier: String,
}

impl AppOperationRequest {
    pub fn new(operation: AppOperationKind, bundle_identifier: impl Into<String>) -> Result<Self> {
        let request = Self {
            operation,
            bundle_identifier: bundle_identifier.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        BundleIdentifier::new(self.bundle_identifier.clone()).map(|_| ())
    }

    pub const fn kind(&self) -> AppOperationKind {
        self.operation
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_identifier
    }

    pub const fn operation_kind(&self) -> OperationKind {
        self.operation.operation_kind()
    }

    pub const fn command_kind(&self) -> CommandKind {
        self.operation.command_kind()
    }

    pub fn eligibility(&self) -> OperationEligibility {
        self.operation_kind().eligibility()
    }

    pub fn check_supervision(&self, evidence: SupervisionEvidence) -> Result<()> {
        self.eligibility().check(evidence)
    }
}

/// The bundle identifier selected for a supervised single-app/kiosk policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KioskPolicy {
    pub bundle_identifier: String,
}

/// Alias for callers that call the policy itself a kiosk configuration.
pub type KioskConfiguration = KioskPolicy;

impl KioskPolicy {
    pub fn new(bundle_identifier: impl Into<String>) -> Result<Self> {
        let policy = Self {
            bundle_identifier: bundle_identifier.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        BundleIdentifier::new(self.bundle_identifier.clone()).map(|_| ())
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_identifier
    }

    pub const fn operation_kind(&self) -> OperationKind {
        OperationKind::KioskMode
    }

    pub const fn required_supervision(&self) -> bool {
        true
    }

    pub fn check_supervision(&self, evidence: SupervisionEvidence) -> Result<()> {
        self.operation_kind().check_supervision(evidence)
    }
}

/// The status values Apple documents for the OS update status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsUpdateStatus {
    Idle,
    Downloading,
    Installing,
    Unknown,
}

/// Compatibility alias matching Apple's response-key capitalization.
#[allow(non_camel_case_types)]
pub type OSUpdateStatus = OsUpdateStatus;

impl FromStr for OsUpdateStatus {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match value {
            "Idle" => Self::Idle,
            "Downloading" => Self::Downloading,
            "Installing" => Self::Installing,
            _ => Self::Unknown,
        })
    }
}

/// A small, protocol-neutral software update inventory record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsUpdateRecord {
    pub product_key: String,
    pub is_downloaded: bool,
    pub download_percent_complete: f64,
    pub status: OsUpdateStatus,
}

impl OsUpdateRecord {
    pub fn new(
        product_key: impl Into<String>,
        is_downloaded: bool,
        download_percent_complete: f64,
        status: OsUpdateStatus,
    ) -> Result<Self> {
        let record = Self {
            product_key: product_key.into(),
            is_downloaded,
            download_percent_complete,
            status,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        validate_operation_text(&self.product_key, "product_key")?;
        if !self.download_percent_complete.is_finite()
            || !(0.0..=1.0).contains(&self.download_percent_complete)
        {
            return Err(TransitionError::InvalidOperationInput(
                "download_percent_complete must be finite and between 0 and 1".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A validated application inventory item returned by an inventory query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationInventoryItem {
    pub bundle_identifier: String,
    pub version: Option<String>,
    pub managed: bool,
}

impl ApplicationInventoryItem {
    pub fn new(
        bundle_identifier: impl Into<String>,
        version: Option<String>,
        managed: bool,
    ) -> Result<Self> {
        let item = Self {
            bundle_identifier: bundle_identifier.into(),
            version,
            managed,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn validate(&self) -> Result<()> {
        BundleIdentifier::new(self.bundle_identifier.clone()).map(|_| ())?;
        if let Some(version) = self.version.as_deref() {
            validate_operation_text(version, "version")?;
        }
        Ok(())
    }
}

/// An application inventory with unique bundle identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApplicationInventory {
    pub items: Vec<ApplicationInventoryItem>,
}

impl ApplicationInventory {
    pub fn new(items: Vec<ApplicationInventoryItem>) -> Result<Self> {
        let inventory = Self { items };
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<()> {
        for (index, item) in self.items.iter().enumerate() {
            item.validate()?;
            if self.items[..index]
                .iter()
                .any(|previous| previous.bundle_identifier == item.bundle_identifier)
            {
                return Err(TransitionError::InvalidOperationInput(format!(
                    "application inventory contains duplicate bundle identifier {:?}",
                    item.bundle_identifier
                )));
            }
        }
        Ok(())
    }

    pub fn find(&self, bundle_identifier: &str) -> Option<&ApplicationInventoryItem> {
        self.items
            .iter()
            .find(|item| item.bundle_identifier == bundle_identifier)
    }
}

fn validate_bundle_identifier(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(TransitionError::InvalidOperationInput(
            "bundle_identifier must not be empty".to_owned(),
        ));
    }
    if value.len() > MAX_BUNDLE_IDENTIFIER_BYTES {
        return Err(TransitionError::InvalidOperationInput(format!(
            "bundle_identifier must be at most {MAX_BUNDLE_IDENTIFIER_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) || value.contains(['/', '\\']) {
        return Err(TransitionError::InvalidOperationInput(
            "bundle_identifier must not contain controls or path separators".to_owned(),
        ));
    }
    Ok(())
}

fn validate_operation_text(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(TransitionError::InvalidOperationInput(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_OPERATION_TEXT_BYTES {
        return Err(TransitionError::InvalidOperationInput(format!(
            "{field} must be at most {MAX_OPERATION_TEXT_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TransitionError::InvalidOperationInput(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervision_unknown_fails_closed_for_sensitive_operations() {
        for operation in [
            OperationKind::KioskMode,
            OperationKind::ScheduleOsUpdate,
            OperationKind::SilentAppInstall,
            OperationKind::AvailableOsUpdates,
            OperationKind::OsUpdateStatus,
        ] {
            assert!(operation.required_supervision());
            assert!(
                operation
                    .check_supervision(SupervisionEvidence::Unknown)
                    .is_err()
            );
            assert!(
                operation
                    .check_supervision(SupervisionEvidence::Unsupervised)
                    .is_err()
            );
            assert!(
                operation
                    .check_supervision(SupervisionEvidence::Supervised)
                    .is_ok()
            );
        }
    }

    #[test]
    fn lock_and_erase_do_not_invent_a_supervision_requirement() {
        for operation in [OperationKind::DeviceLock, OperationKind::EraseDevice] {
            assert!(!operation.required_supervision());
            assert!(
                operation
                    .check_supervision(SupervisionEvidence::Unknown)
                    .is_ok()
            );
        }
    }

    #[test]
    fn app_operations_map_to_wire_command_families() {
        let silent =
            AppOperationRequest::new(AppOperationKind::SilentInstall, "com.example.app").unwrap();
        assert_eq!(silent.command_kind(), CommandKind::InstallApplication);
        assert!(
            silent
                .check_supervision(SupervisionEvidence::Unknown)
                .is_err()
        );

        let remove = AppOperationRequest::new(AppOperationKind::Remove, "com.example.app").unwrap();
        assert_eq!(remove.command_kind(), CommandKind::RemoveApplication);
        assert!(
            remove
                .check_supervision(SupervisionEvidence::Unknown)
                .is_ok()
        );
    }

    #[test]
    fn inventory_rejects_invalid_or_duplicate_items() {
        let first =
            ApplicationInventoryItem::new("com.example.app", Some("1.0".into()), true).unwrap();
        assert!(ApplicationInventory::new(vec![first.clone(), first]).is_err());
        assert!(BundleIdentifier::new("../app").is_err());
        assert!(ApplicationInventoryItem::new("com.example.app", Some("\n".into()), true).is_err());
    }

    #[test]
    fn update_records_validate_progress_and_preserve_unknown_statuses() {
        let record =
            OsUpdateRecord::new("iPadOS-17.7", false, 0.25, OsUpdateStatus::Downloading).unwrap();
        assert_eq!(record.status, OsUpdateStatus::Downloading);
        assert!(OsUpdateRecord::new("x", false, 1.1, OsUpdateStatus::Idle).is_err());
        assert_eq!(
            "Future".parse::<OsUpdateStatus>().unwrap(),
            OsUpdateStatus::Unknown
        );
    }
}
