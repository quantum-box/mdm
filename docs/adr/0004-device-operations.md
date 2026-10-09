# ADR 0004: Device operation boundaries and timeout policy

- Status: accepted
- Date: 2026-10-10
- License: MIT

## Context

The MDM service needs to cover application inventory and management, supervised
kiosk policy, Automated Device Enrollment (ADE) setup, operating-system update
queries, device lock, and device erase. These operations have different Apple
channel and supervision requirements. A transport response timeout also has a
different meaning for a query than it has for a command that may already have
changed the device.

Apple's public device-management schema is the source of command names and
the selected iPadOS capability boundary:

- [Apple device-management schemas](https://github.com/apple/device-management)
- [Installed Application List](https://github.com/apple/device-management/blob/release/mdm/commands/application.installed.list.yaml)
- [Managed Application List](https://github.com/apple/device-management/blob/release/mdm/commands/application.managed.list.yaml)
- [Available OS Updates](https://github.com/apple/device-management/blob/release/mdm/commands/system.update.available.yaml)
- [OS Update Status](https://github.com/apple/device-management/blob/release/mdm/commands/system.update.status.yaml)
- [Schedule OS Update](https://github.com/apple/device-management/blob/release/mdm/commands/system.update.schedule.yaml)
- [Device Lock](https://github.com/apple/device-management/blob/release/mdm/commands/device.lock.yaml)
- [Erase Device](https://github.com/apple/device-management/blob/release/mdm/commands/device.erase.yaml)
- [AppManaged declaration](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.managed.yaml)
- [Automated Device Enrollment](https://developer.apple.com/documentation/devicemanagement/device-enrollment)

## Decision

`mdm-core` exposes protocol-independent `OperationKind` values. The command
families that have an Apple MDM request type retain the Apple spelling in the
corresponding `CommandKind` values: `InstalledApplicationList`,
`ManagedApplicationList`, `AvailableOsUpdates`, `OsUpdateStatus`,
`InstallApplication`, `RemoveApplication`, `ScheduleOsUpdate`, `DeviceLock`,
`EraseDevice`, `EnableLostMode`, `DisableLostMode`, and `DeviceConfigured`.
`DeclarativeManagement`, profile commands, and `DeviceInformation` remain
available from the earlier boundary.

The following command families are read-only and return from
`AwaitingResponse` to `Queued` on a timeout:

- `DeviceInformation`
- `InstalledApplicationList`
- `ManagedApplicationList`
- `AvailableOsUpdates`
- `OsUpdateStatus`

Every other command becomes `OutcomeUnknown` on a response timeout. The device
may have applied a mutation even when the server did not receive a response;
the application layer must resolve that state with a device report, a
carefully chosen reconciliation operation, or an explicit administrator
decision before issuing another mutation.

`OperationKind::required_supervision()` is the single policy flag used by the
application layer. It is true for kiosk mode, silent app installation,
`AvailableOsUpdates`, `OsUpdateStatus`, `ScheduleOsUpdate`, Lost Mode, and
`DeviceConfigured`. The Apple schema describes device-lock and erase as
available without supervision, so those operations do not acquire an invented
supervision requirement here. The service still enforces Apple access rights,
enrollment channel, and device capabilities at the protocol/application
boundary.

`SupervisionEvidence::Unknown` fails closed for every operation whose policy
flag is true. ADE is represented by `EnrollmentMode::AutomatedDeviceEnrollment`
but does not itself prove supervision; the service must retain and evaluate
device-reported supervision evidence separately. `EnrollmentMode::UserEnrollment`
does not bypass the policy check.

`AppOperationRequest` validates a bundle identifier and maps install, update,
remove, and silent-install intents to the command and operation families.
`KioskPolicy` validates a single bundle identifier and always requires
supervision. `ApplicationInventory` rejects duplicate bundle identifiers.
`OsUpdateRecord` retains only the stable status values in the selected core
boundary (`Idle`, `Downloading`, and `Installing`) and maps future values to
`Unknown` without fabricating completion.

The selected DDM boundary also supports
`com.apple.configuration.app.managed` for iPadOS 17.2 and later. It accepts one
of `AppStoreID` or `BundleID`, an explicit `InstallBehavior` license assignment,
and the `Optional`/`Required` install mode. Manifest URLs, composed identifiers,
macOS-only attributes, and other app configuration keys remain outside this
engine boundary. A `Required` app install is treated as a silent-install policy
by callers and therefore must pass the supervision check. Traditional MDM
profiles retain ownership of settings unless a future explicit bridge is
implemented.

Device erase is destructive. `mdm-core` only models the operation and its
ambiguous delivery state; the root application is responsible for durable
confirmation, authorization, audit, and any platform-specific erase options
before enqueueing `EraseDevice`.

## Consequences

The core crate stays independent of HTTP, SQLite, APNs, plist encoding, and
Apple transport details. The root service must persist supervision evidence and
the selected enrollment mode with each enrollment generation, map protocol
payloads to the canonical command kinds, and preserve the `OutcomeUnknown`
barrier across restarts. Query retries are safe only for the listed read-only
families; a command that merely looks like a query must not be placed in that
set without an explicit Apple schema review.
