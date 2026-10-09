# Protocol sources

This crate follows the device-channel subset of Apple’s public MDM schema. The
schema input is pinned to the `release` branch commit below so that changes in
Apple’s rolling repository do not silently change the wire contract.

## Pinned schema release

- Repository: [apple/device-management](https://github.com/apple/device-management)
- Release commit: [`09f249a06e7e3289930bf6d05f38fb562f748ebf`](https://github.com/apple/device-management/tree/09f249a06e7e3289930bf6d05f38fb562f748ebf)
- Resolved from `refs/heads/release` on 2026-10-09 with `git ls-remote`.
- Relevant schema directories at that commit:
  - [check-in requests](https://github.com/apple/device-management/tree/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/checkin)
  - [MDM commands](https://github.com/apple/device-management/tree/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands)
  - [MDM profiles](https://github.com/apple/device-management/tree/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/profiles)
  - [DDM protocol schemas](https://github.com/apple/device-management/tree/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/protocol)
  - [DDM check-in schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/checkin/declarativemanagement.yaml)
  - [DDM command schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/declarativemanagement.yaml)
  - [TokensResponse schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/protocol/tokensresponse.yaml)
  - [DeclarationItemsResponse schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/protocol/declarationitemsresponse.yaml)
  - [StatusReport schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/protocol/statusreport.yaml)
  - [DDM declaration base schema](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/declarations/declarationbase.yaml)
  - [DDM server-capabilities declaration](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/declarative/declarations/management/server-capabilities.yaml)
  - [InstallApplication command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/application.install.yaml)
  - [RemoveApplication command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/application.remove.yaml)
  - [InstalledApplicationList command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/application.installed.list.yaml)
  - [ManagedApplicationList command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/application.managed.list.yaml)
  - [AvailableOSUpdates command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/system.update.available.yaml)
  - [ScheduleOSUpdate command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/system.update.schedule.yaml)
  - [OSUpdateStatus command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/system.update.status.yaml)
  - [DeviceLock command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/device.lock.yaml)
  - [EraseDevice command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/device.erase.yaml)
  - [DeviceConfigured command](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/commands/device.configured.yaml)
  - [App Lock profile](https://github.com/apple/device-management/blob/09f249a06e7e3289930bf6d05f38fb562f748ebf/mdm/profiles/com.apple.app.lock.yaml)
  - [MDM AccessRights](https://developer.apple.com/documentation/devicemanagement/mdm)

Apple publishes this repository as schema data, not as a server implementation.
The commit records the source used for the initial implementation; it does not
claim that every schema item or every Apple OS release is supported here.

## Apple protocol references

- [MDM](https://developer.apple.com/documentation/devicemanagement/mdm) —
  device-management protocol overview and enrollment context.
- [Check-in](https://developer.apple.com/documentation/devicemanagement/check-in)
  — device-channel check-in message types and fields.
- [Sending MDM commands to a device](https://developer.apple.com/documentation/devicemanagement/sending-mdm-commands-to-a-device)
  — polling, command UUID correlation, response statuses, and empty HTTP
  responses.
- [Device Information](https://developer.apple.com/documentation/devicemanagement/device-information-command)
  — the command request and query model used by `DeviceInformation`.
- [Setting up push notifications for your device management customers](https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers)
  — MDM push certificate and topic requirements.
- [Requesting access to an MDM Vendor CSR Signing Certificate](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate)
  — vendor certificate prerequisite for obtaining a customer MDM push
  certificate.
- [Declarative management](https://developer.apple.com/documentation/devicemanagement/declarative-management)
  — the device-channel endpoints (`tokens`, `declaration-items`, `status`, and
  `declaration/<type>/<identifier>`) and their HTTP behavior.
- [DeclarativeManagementRequest](https://developer.apple.com/documentation/devicemanagement/declarativemanagementrequest)
  — the check-in plist envelope and the JSON-in-`Data` contract.
- [DeclarativeManagementCommand](https://developer.apple.com/documentation/devicemanagement/declarativemanagementcommand)
  — the command data contract used to activate or synchronize DDM.
- [TokensResponse](https://developer.apple.com/documentation/devicemanagement/tokensresponse),
  [DeclarationItemsResponse](https://developer.apple.com/documentation/devicemanagement/declarationitemsresponse),
  and [StatusReport](https://developer.apple.com/documentation/devicemanagement/statusreport)
  — the JSON wire schemas implemented by this crate.
- [Integrating declarative management](https://developer.apple.com/documentation/devicemanagement/integrating-declarative-management)
  — activation and synchronization lifecycle.

## Implemented subset and deliberate boundaries

`mdm-protocol` implements `Authenticate`, `TokenUpdate`, `CheckOut`, and the
device-channel `DeclarativeManagement` check-in. DDM endpoints are parsed into
typed paths, and status `Data` is bounded JSON. It also exposes validated wire
types for `TokensResponse`, `DeclarationItemsResponse`, and `StatusReport`.
The command side supports `DeviceInformation`, profile install/removal,
application install/removal and inventory, device lock/erase, the
`DeviceConfigured` ADE release command, legacy operating-system update
queries/scheduling, and the DDM activation/synchronization command. App Store
installation is restricted to a positive iTunes Store ID with Apple's
device-license `PurchaseMethod=1`; enterprise installation is restricted to an
HTTPS `ManifestURL`. DDM command data is the optional `TokensResponse` JSON
object encoded as plist `<data>`.
The pinned `ScheduleOSUpdate` schema makes `ProductVersion` available on iOS
from 11.3, while `MaxUserDeferrals`, `Priority`, `NotifyOnly`,
`InstallLater`, and `InstallForceRestart` are macOS-only fields/actions. The
protocol crate encodes the complete schema range; `mdmd` currently admits the
cross-platform-safe subset and rejects those macOS-only options until the
enrollment has an explicit platform capability record.
The crate preserves the raw response plist for auditing while requiring a
command UUID on non-`Idle` responses and rejecting a UUID on `Idle`.

Enrollment profiles contain the root CA, SCEP, and MDM payloads. The MDM
payload uses `/mdm` and `/checkin`, advertises access rights `4383` (profile
inspection/install, lock, erase, device information, application inspection,
and application management), and omits `ServerCapabilities`. Apple enables DDM by delivering the
`DeclarativeManagement` command; the enrollment profile does not need a
`com.apple.mdm.per-user-connections` capability for device-channel DDM.
The `kiosk_profile` helper emits a deterministic supervised-device
`com.apple.app.lock` profile from a bundle ID, profile identifier, and caller
UUID. `AwaitingConfiguration` remains a parsed TokenUpdate fact so the core
can gate the ADE-only `DeviceConfigured` command instead of rejecting the
check-in. User-channel fields and unsupported check-in message types are
rejected explicitly. Declaration assignment and declaration payload validation
remain above this wire crate so the core can own its generation and revision
rules.
