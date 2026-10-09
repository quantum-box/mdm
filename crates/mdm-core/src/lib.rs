//! Protocol-independent domain types for an Apple MDM engine.
//!
//! This crate deliberately stops at the state and data boundary. It does not
//! open network connections, persist data, or implement an Apple protocol.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

mod ddm;
mod operations;

pub use ddm::*;
pub use operations::*;

/// The result type returned by state transitions and declaration validation.
pub type Result<T> = std::result::Result<T, TransitionError>;

/// The lifecycle of an enrollment identity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    /// No valid authentication has completed yet.
    #[default]
    Pending,
    /// The enrollment has authenticated and may receive a token update.
    Authenticated,
    /// The enrollment is actively usable.
    Active,
    /// The enrollment can no longer be used.
    Revoked,
}

impl EnrollmentState {
    /// Complete authentication for this enrollment.
    ///
    /// Authentication is idempotent after it has already succeeded. A
    /// revoked enrollment never becomes usable again.
    pub fn authenticate(self) -> Result<Self> {
        match self {
            Self::Pending => Ok(Self::Authenticated),
            Self::Authenticated | Self::Active => Ok(self),
            Self::Revoked => Err(TransitionError::EnrollmentRevoked),
        }
    }

    /// Apply a token update and activate an authenticated enrollment.
    ///
    /// A token update is accepted only after authentication. The transition
    /// from `Authenticated` to `Active` is idempotent for an already active
    /// enrollment. This method does not claim that the token is valid; token
    /// verification belongs to the protocol or persistence layer outside this
    /// crate.
    pub fn token_update(self) -> Result<Self> {
        match self {
            Self::Authenticated => Ok(Self::Active),
            Self::Active => Ok(Self::Active),
            Self::Pending => Err(TransitionError::TokenUpdateRequiresAuthentication),
            Self::Revoked => Err(TransitionError::EnrollmentRevoked),
        }
    }

    /// Revoke an enrollment. Revocation is idempotent.
    pub fn revoke(self) -> Self {
        Self::Revoked
    }
}

/// The command families represented by the core engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    /// A read-only device information request. It is safe to retry after a
    /// transport timeout because it has no intended device-side mutation.
    DeviceInformation,
    /// A read-only inventory query for all installed applications.
    InstalledApplicationList,
    /// A read-only query for applications managed by the MDM service.
    ManagedApplicationList,
    /// A read-only query for operating-system updates available to the
    /// device. The response can be retried after a transport timeout.
    AvailableOsUpdates,
    /// A read-only query for operating-system update status.
    OsUpdateStatus,
    /// A command that installs or updates a configuration profile.
    InstallProfile,
    /// A command that removes a configuration profile.
    RemoveProfile,
    /// A command that installs or updates an application.
    InstallApplication,
    /// A command that removes a managed application.
    RemoveApplication,
    /// A command that schedules an operating-system update.
    ScheduleOsUpdate,
    /// Remotely lock a device.
    DeviceLock,
    /// Erase a device. The application layer must obtain any required durable
    /// confirmation before enqueueing this command.
    EraseDevice,
    /// Enable supervised Lost Mode.
    EnableLostMode,
    /// Disable supervised Lost Mode.
    DisableLostMode,
    /// Complete an Automated Device Enrollment setup flow.
    DeviceConfigured,
    /// A declarative-management synchronization request. DDM can apply
    /// configurations autonomously, so a lost response is ambiguous in the
    /// same way as a profile mutation.
    DeclarativeManagement,
}

impl CommandKind {
    /// Compatibility spelling matching Apple's all-caps acronym in the wire
    /// request type. The canonical Rust variant is `AvailableOsUpdates`.
    #[allow(non_upper_case_globals)]
    pub const AvailableOSUpdates: Self = Self::AvailableOsUpdates;
    /// Compatibility spelling matching Apple's all-caps acronym in the wire
    /// request type. The canonical Rust variant is `OsUpdateStatus`.
    #[allow(non_upper_case_globals)]
    pub const OSUpdateStatus: Self = Self::OsUpdateStatus;
    /// Compatibility spelling matching Apple's all-caps acronym in the wire
    /// request type. The canonical Rust variant is `ScheduleOsUpdate`.
    #[allow(non_upper_case_globals)]
    pub const ScheduleOSUpdate: Self = Self::ScheduleOsUpdate;
    #[allow(non_upper_case_globals)]
    pub const DeviceWipe: Self = Self::EraseDevice;

    /// Whether this command is a read-only query whose transport timeout can
    /// safely return it to the queue.
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

    pub const fn retry_after_timeout(self) -> bool {
        self.is_read_only()
    }

    pub const fn timeout_is_ambiguous(self) -> bool {
        !self.is_read_only()
    }

    /// The operation policy corresponding to this wire command family.
    pub const fn operation_kind(self) -> OperationKind {
        match self {
            Self::DeviceInformation => OperationKind::DeviceInformation,
            Self::InstalledApplicationList => OperationKind::InstalledApplicationList,
            Self::ManagedApplicationList => OperationKind::ManagedApplicationList,
            Self::AvailableOsUpdates => OperationKind::AvailableOsUpdates,
            Self::OsUpdateStatus => OperationKind::OsUpdateStatus,
            Self::InstallProfile => OperationKind::InstallProfile,
            Self::RemoveProfile => OperationKind::RemoveProfile,
            Self::InstallApplication => OperationKind::InstallApplication,
            Self::RemoveApplication => OperationKind::RemoveApplication,
            Self::ScheduleOsUpdate => OperationKind::ScheduleOsUpdate,
            Self::DeviceLock => OperationKind::DeviceLock,
            Self::EraseDevice => OperationKind::EraseDevice,
            Self::EnableLostMode => OperationKind::EnableLostMode,
            Self::DisableLostMode => OperationKind::DisableLostMode,
            Self::DeviceConfigured => OperationKind::DeviceConfigured,
            Self::DeclarativeManagement => OperationKind::DeclarativeManagement,
        }
    }

    /// Whether the command's selected iPadOS operation requires supervision.
    pub const fn required_supervision(self) -> bool {
        self.operation_kind().required_supervision()
    }

    /// Build the supervision policy for this command.
    pub const fn eligibility(self) -> OperationEligibility {
        self.operation_kind().eligibility()
    }
}

/// The delivery lifecycle of one command.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    /// The command has not been sent.
    #[default]
    Queued,
    /// The command is in flight and a response is expected.
    AwaitingResponse,
    /// The device asked the caller to retry later.
    Deferred,
    /// The device acknowledged the command.
    Completed,
    /// The device rejected the command or reported a command error.
    Failed,
    /// A timeout leaves execution on the device uncertain.
    OutcomeUnknown,
    /// The command will not be delivered or accepted locally.
    Cancelled,
}

impl CommandState {
    /// Move a queued or deferred command into delivery.
    pub fn dispatch(self) -> Result<Self> {
        match self {
            Self::Queued | Self::Deferred => Ok(Self::AwaitingResponse),
            Self::Cancelled => Err(TransitionError::CommandCancelled),
            _ => Err(TransitionError::CommandNotDispatchable { state: self }),
        }
    }

    /// Apply a device response to this command.
    ///
    /// An ambiguous delivery (`OutcomeUnknown`) may be resolved by a late
    /// response. A deferred command may also receive a delayed terminal reply
    /// from its earlier delivery attempt. Completed and failed states accept
    /// only a duplicate response with the same terminal meaning, so a late
    /// response cannot resurrect a terminal command into a different result.
    pub fn respond(self, reply: Reply) -> Result<Self> {
        match self {
            Self::AwaitingResponse | Self::Deferred | Self::OutcomeUnknown => {
                Ok(Self::state_for_reply(reply))
            }
            Self::Completed if reply == Reply::Acknowledged => Ok(Self::Completed),
            Self::Failed if reply.is_error() => Ok(Self::Failed),
            Self::Cancelled => Err(TransitionError::CommandCancelled),
            _ => Err(TransitionError::ResponseNotAllowed { state: self, reply }),
        }
    }

    /// Resolve a response timeout according to the command's retry safety.
    ///
    /// Read-only queries return to the queue. Every mutation becomes
    /// `OutcomeUnknown`, because assuming that a timed-out mutation did not
    /// execute could apply it twice or undo a device-side change.
    pub fn timeout(self, kind: CommandKind) -> Self {
        match (self, kind) {
            (Self::AwaitingResponse, CommandKind::DeviceInformation) => Self::Queued,
            (
                Self::AwaitingResponse,
                CommandKind::InstalledApplicationList
                | CommandKind::ManagedApplicationList
                | CommandKind::AvailableOsUpdates
                | CommandKind::OsUpdateStatus,
            ) => Self::Queued,
            (
                Self::AwaitingResponse,
                CommandKind::InstallProfile
                | CommandKind::RemoveProfile
                | CommandKind::InstallApplication
                | CommandKind::RemoveApplication
                | CommandKind::ScheduleOsUpdate
                | CommandKind::DeviceLock
                | CommandKind::EraseDevice
                | CommandKind::EnableLostMode
                | CommandKind::DisableLostMode
                | CommandKind::DeviceConfigured
                | CommandKind::DeclarativeManagement,
            ) => Self::OutcomeUnknown,
            (state, _) => state,
        }
    }

    /// Cancel a command unless it has already reached a known result.
    pub fn cancel(self) -> Self {
        match self {
            Self::Completed | Self::Failed => self,
            _ => Self::Cancelled,
        }
    }

    /// Whether the state is a known final result.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    fn state_for_reply(reply: Reply) -> Self {
        match reply {
            Reply::Acknowledged => Self::Completed,
            Reply::Error | Reply::CommandFormatError => Self::Failed,
            Reply::NotNow => Self::Deferred,
        }
    }
}

/// Responses a device may return for a delivered command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    /// The command was accepted and completed.
    Acknowledged,
    /// The device reported a command failure.
    Error,
    /// The device could not parse or validate the command format.
    CommandFormatError,
    /// The command should be attempted again later.
    NotNow,
}

impl Reply {
    const fn is_error(self) -> bool {
        matches!(self, Self::Error | Self::CommandFormatError)
    }
}

/// Errors raised when a state or declaration transition is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransitionError {
    #[error("an enrollment in the revoked state cannot be used")]
    EnrollmentRevoked,
    #[error("a token update requires an authenticated or active enrollment")]
    TokenUpdateRequiresAuthentication,
    #[error("command state {state:?} cannot be dispatched")]
    CommandNotDispatchable { state: CommandState },
    #[error("response {reply:?} is not allowed while command is in state {state:?}")]
    ResponseNotAllowed { state: CommandState, reply: Reply },
    #[error("a cancelled command cannot be changed")]
    CommandCancelled,
    #[error("declaration id must not be empty")]
    EmptyDeclarationId,
    #[error("declaration version must not be empty")]
    EmptyDeclarationVersion,
    #[error("invalid Apple DDM declaration: {0}")]
    InvalidDdmDeclaration(String),
    #[error("invalid Apple DDM target OS version: {0}")]
    InvalidDdmOsVersion(String),
    #[error("Apple DDM declaration is not supported for this iPadOS target: {0}")]
    UnsupportedDdmTarget(String),
    #[error("operation {operation:?} requires supervised device evidence, received {evidence:?}")]
    OperationRequiresSupervision {
        operation: OperationKind,
        evidence: SupervisionEvidence,
    },
    #[error("invalid device operation: {0}")]
    InvalidOperationInput(String),
}

/// An opaque Apple DDM declaration at the core boundary.
///
/// The payload remains a `serde_json::Value` so protocol-specific declaration
/// types can be added by a higher layer without making this crate depend on
/// transport or device protocol code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Declaration {
    pub id: String,
    pub version: String,
    pub payload: Value,
}

impl Declaration {
    /// Construct and validate a declaration.
    pub fn new(id: impl Into<String>, version: impl Into<String>, payload: Value) -> Result<Self> {
        let declaration = Self {
            id: id.into(),
            version: version.into(),
            payload,
        };
        declaration.validate()?;
        Ok(declaration)
    }

    /// Alias for callers that prefer a fallible-constructor name.
    pub fn try_new(
        id: impl Into<String>,
        version: impl Into<String>,
        payload: Value,
    ) -> Result<Self> {
        Self::new(id, version, payload)
    }

    /// Check the required declaration identity fields.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(TransitionError::EmptyDeclarationId);
        }
        if self.version.trim().is_empty() {
            return Err(TransitionError::EmptyDeclarationVersion);
        }
        Ok(())
    }

    /// Whether two declarations identify the same exact version token.
    ///
    /// Apple declaration versions are opaque equality tokens. This method
    /// therefore does not parse, normalize, or order them, and it also avoids
    /// treating versions belonging to different declaration identifiers as the
    /// same version.
    pub fn same_version(&self, other: &Self) -> bool {
        self.id == other.id && self.version == other.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enrollment_authentication_is_idempotent_but_revocation_is_final() {
        let cases = [
            (EnrollmentState::Pending, Ok(EnrollmentState::Authenticated)),
            (
                EnrollmentState::Authenticated,
                Ok(EnrollmentState::Authenticated),
            ),
            (EnrollmentState::Active, Ok(EnrollmentState::Active)),
        ];

        for (state, expected) in cases {
            assert_eq!(state.authenticate(), expected);
        }
        assert_eq!(
            EnrollmentState::Revoked.authenticate(),
            Err(TransitionError::EnrollmentRevoked)
        );

        for state in [
            EnrollmentState::Pending,
            EnrollmentState::Authenticated,
            EnrollmentState::Active,
            EnrollmentState::Revoked,
        ] {
            assert_eq!(state.revoke(), EnrollmentState::Revoked);
        }
        assert_eq!(
            EnrollmentState::Revoked.authenticate(),
            Err(TransitionError::EnrollmentRevoked)
        );
    }

    #[test]
    fn token_updates_require_a_usable_enrollment() {
        assert_eq!(
            EnrollmentState::Authenticated.token_update(),
            Ok(EnrollmentState::Active)
        );
        assert_eq!(
            EnrollmentState::Active.token_update(),
            Ok(EnrollmentState::Active)
        );
        assert_eq!(
            EnrollmentState::Pending.token_update(),
            Err(TransitionError::TokenUpdateRequiresAuthentication)
        );
        assert_eq!(
            EnrollmentState::Revoked.token_update(),
            Err(TransitionError::EnrollmentRevoked)
        );
    }

    #[test]
    fn dispatch_only_starts_queued_or_deferred_commands() {
        let expected = [
            (CommandState::Queued, Ok(CommandState::AwaitingResponse)),
            (CommandState::Deferred, Ok(CommandState::AwaitingResponse)),
        ];
        for (state, result) in expected {
            assert_eq!(state.dispatch(), result);
        }

        for state in [
            CommandState::AwaitingResponse,
            CommandState::Completed,
            CommandState::Failed,
            CommandState::OutcomeUnknown,
        ] {
            assert!(state.dispatch().is_err());
        }
        assert_eq!(
            CommandState::Cancelled.dispatch(),
            Err(TransitionError::CommandCancelled)
        );
    }

    #[test]
    fn replies_map_to_their_expected_states() {
        let cases = [
            (Reply::Acknowledged, CommandState::Completed),
            (Reply::Error, CommandState::Failed),
            (Reply::CommandFormatError, CommandState::Failed),
            (Reply::NotNow, CommandState::Deferred),
        ];
        for (reply, expected) in cases {
            assert_eq!(CommandState::AwaitingResponse.respond(reply), Ok(expected));
            assert_eq!(CommandState::Deferred.respond(reply), Ok(expected));
            assert_eq!(CommandState::OutcomeUnknown.respond(reply), Ok(expected));
        }
    }

    #[test]
    fn duplicate_terminal_replies_are_idempotent_without_resurrection() {
        assert_eq!(
            CommandState::Completed.respond(Reply::Acknowledged),
            Ok(CommandState::Completed)
        );
        assert_eq!(
            CommandState::Failed.respond(Reply::Error),
            Ok(CommandState::Failed)
        );
        assert_eq!(
            CommandState::Failed.respond(Reply::CommandFormatError),
            Ok(CommandState::Failed)
        );

        for reply in [Reply::Error, Reply::CommandFormatError, Reply::NotNow] {
            assert!(CommandState::Completed.respond(reply).is_err());
        }
        assert!(CommandState::Failed.respond(Reply::Acknowledged).is_err());
        assert!(CommandState::Failed.respond(Reply::NotNow).is_err());
    }

    #[test]
    fn cancelled_commands_reject_every_response() {
        for reply in [
            Reply::Acknowledged,
            Reply::Error,
            Reply::CommandFormatError,
            Reply::NotNow,
        ] {
            assert_eq!(
                CommandState::Cancelled.respond(reply),
                Err(TransitionError::CommandCancelled)
            );
        }
    }

    #[test]
    fn timeouts_retry_only_read_only_information() {
        for kind in [
            CommandKind::DeviceInformation,
            CommandKind::InstalledApplicationList,
            CommandKind::ManagedApplicationList,
            CommandKind::AvailableOsUpdates,
            CommandKind::OsUpdateStatus,
        ] {
            assert!(kind.is_read_only());
            assert_eq!(
                CommandState::AwaitingResponse.timeout(kind),
                CommandState::Queued
            );
        }
        for kind in [
            CommandKind::InstallProfile,
            CommandKind::RemoveProfile,
            CommandKind::InstallApplication,
            CommandKind::RemoveApplication,
            CommandKind::ScheduleOsUpdate,
            CommandKind::DeviceLock,
            CommandKind::EraseDevice,
            CommandKind::EnableLostMode,
            CommandKind::DisableLostMode,
            CommandKind::DeviceConfigured,
            CommandKind::DeclarativeManagement,
        ] {
            assert!(!kind.is_read_only());
            assert_eq!(
                CommandState::AwaitingResponse.timeout(kind),
                CommandState::OutcomeUnknown
            );
        }

        for state in [
            CommandState::Queued,
            CommandState::Deferred,
            CommandState::Completed,
            CommandState::Failed,
            CommandState::OutcomeUnknown,
            CommandState::Cancelled,
        ] {
            for kind in [
                CommandKind::DeviceInformation,
                CommandKind::InstalledApplicationList,
                CommandKind::ManagedApplicationList,
                CommandKind::AvailableOsUpdates,
                CommandKind::OsUpdateStatus,
                CommandKind::InstallProfile,
                CommandKind::RemoveProfile,
                CommandKind::InstallApplication,
                CommandKind::RemoveApplication,
                CommandKind::ScheduleOsUpdate,
                CommandKind::DeviceLock,
                CommandKind::EraseDevice,
                CommandKind::EnableLostMode,
                CommandKind::DisableLostMode,
                CommandKind::DeviceConfigured,
                CommandKind::DeclarativeManagement,
            ] {
                assert_eq!(state.timeout(kind), state);
            }
        }
    }

    #[test]
    fn command_names_keep_apple_acronym_aliases_and_operation_policies() {
        assert_eq!(
            CommandKind::AvailableOSUpdates,
            CommandKind::AvailableOsUpdates
        );
        assert_eq!(CommandKind::OSUpdateStatus, CommandKind::OsUpdateStatus);
        assert_eq!(CommandKind::ScheduleOSUpdate, CommandKind::ScheduleOsUpdate);
        assert!(CommandKind::AvailableOsUpdates.required_supervision());
        assert!(CommandKind::ScheduleOsUpdate.required_supervision());
        assert!(!CommandKind::DeviceLock.required_supervision());
        assert_eq!(
            serde_json::to_string(&CommandKind::InstalledApplicationList).unwrap(),
            "\"installed_application_list\""
        );
    }

    #[test]
    fn cancellation_preserves_known_results() {
        assert_eq!(CommandState::Completed.cancel(), CommandState::Completed);
        assert_eq!(CommandState::Failed.cancel(), CommandState::Failed);
        for state in [
            CommandState::Queued,
            CommandState::AwaitingResponse,
            CommandState::Deferred,
            CommandState::OutcomeUnknown,
            CommandState::Cancelled,
        ] {
            assert_eq!(state.cancel(), CommandState::Cancelled);
        }
    }

    #[test]
    fn declaration_validation_and_version_tokens_are_exact() {
        assert!(Declaration::new("", "1", json!({})).is_err());
        assert!(Declaration::new("id", "", json!({})).is_err());
        assert!(Declaration::new("  ", "1", json!({})).is_err());
        assert!(Declaration::new("id", "  ", json!({})).is_err());

        let v1 = Declaration::new("id", "v1", json!({"v": 1})).unwrap();
        let v1_same = Declaration::new("id", "v1", json!({"other": true})).unwrap();
        let v1_0 = Declaration::new("id", "v1.0", json!({})).unwrap();
        let other_id = Declaration::new("other-id", "v1", json!({})).unwrap();
        assert!(v1.same_version(&v1_same));
        assert!(!v1.same_version(&v1_0));
        assert!(!v1.same_version(&other_id));

        let encoded = serde_json::to_string(&v1).unwrap();
        let decoded: Declaration = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, v1);
    }

    #[test]
    fn every_state_and_reply_preserves_terminal_invariants() {
        let replies = [
            Reply::Acknowledged,
            Reply::Error,
            Reply::CommandFormatError,
            Reply::NotNow,
        ];
        for state in [CommandState::Completed, CommandState::Failed] {
            for reply in replies {
                if let Ok(next) = state.respond(reply) {
                    assert_eq!(next, state);
                }
            }
        }
        for reply in replies {
            assert!(CommandState::Cancelled.respond(reply).is_err());
        }
    }
}
