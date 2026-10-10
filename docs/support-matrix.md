# Support matrix

The matrix describes the current implementation boundary and evidence level.
“Schema” means the protocol shape is represented in code. “Real test” requires
an Apple-issued MDM push certificate, public HTTPS, and a physical device.

| Area | Initial implementation | Evidence today | Next acceptance step |
| --- | --- | --- | --- |
| iOS / iPadOS device channel | Authenticate, TokenUpdate, CheckOut, DeviceInformation, InstallProfile, RemoveProfile, application operations, OS updates, lock, and erase | Synthetic fixtures and local tests only | M1/M2 real iPad enrollment and command round trip |
| macOS device channel | Same device-channel subset | Synthetic fixtures and local tests only | M1/M2 supervised/device-channel test |
| tvOS | Protocol fields are shared with the device-channel subset | No physical-device evidence | Test with an Apple TV and matching certificate |
| visionOS | Protocol fields are shared with the device-channel subset | No physical-device evidence | Test with a Vision Pro and matching certificate |
| watchOS | Profile schema is represented, with no watch-specific acceptance | No physical-device evidence | Test with a supported watch enrollment path |
| macOS / Shared iPad user channel | Rejected explicitly | Parser boundary tests | Separate user-channel design and authorization review |
| Application management (iPad device channel) | Installed/managed application inventory, device-based App Store install, HTTPS Enterprise manifest install, and remove | Synthetic command, policy, API, CLI, and UI tests | Real supervised iPad install, observation, and remove |
| Supervised kiosk | Deterministic `com.apple.app.lock` profile apply/release with supervision and installed-application evidence gates | Synthetic policy, command, API, CLI, and UI tests | Real supervised iPad kiosk apply, launch restriction, and release |
| Automated Device Enrollment | Encrypted server-token loading, OAuth session, device/profile sync, profile definition, assignment/removal, and CMS-signed MachineInfo bootstrap | Loopback protocol fixtures and signed CMS/parser tests only | Apple Business/School Manager tenant, assigned serial, and real bootstrap |
| Apps & Books (VPP) | Device-based location-token loading, asset lookup, associate/disassociate, asynchronous status, and per-device assignment lookup | Loopback endpoint and secret-redaction tests only | Apple device-assignable asset, event completion, and real device install/remove |
| OS updates | Available/update-status queries and explicit schedule policy for the supported iPad subset | Synthetic protocol, policy, API, CLI, and UI tests | Real iPad update query, schedule, and observed completion |
| Device lock and erase | Administrator-authorized lock; two-step serial-confirmed erase intent and command with audit trail | Synthetic policy, API, CLI, and UI tests | Lock a test iPad and erase only a disposable authorized device |
| iPadOS DDM device channel (16+) | Four declaration types, including AppManaged from 17.2, per-generation assignments, tokens/manifest/fetch/status, API/CLI | Synthetic domain/protocol/SQLite/HTTP tests | M3 real iPad application, update/delete, status and coexistence |
| APNs | Certificate-authenticated MDM push through `api.push.apple.com` | Code path only; no Apple credential | Use a customer-specific MDM Push Certificate |
| SCEP | Local CA and device identity issuance path | Local synthetic/SCEP checks | Verify with a real Apple-generated enrollment profile |
| Public TLS / reverse proxy | Built-in TLS with client-certificate peer binding, or loopback service with verified proxy headers | Synthetic configuration and HTTP checks only | Validate the complete TLS chain on a real device |
| Cloudflare / Lambda gateways | Worker and API Gateway HTTP API v2 adapters share signed forwarding, certificate context, binary bodies, and bounded requests/responses; Lambda SAM template included | Synthetic gateway and canonical Rust/JS contract tests; Worker bundle dry run | Deploy to a configured zone/account and verify issued device certificates and bootstrap over public HTTPS |
| Portable origin runtime | Docker/Compose with a persistent SQLite volume, private secret copies, strict TLS health probe, and async notification ports | Container startup/restart smoke is enforced in CI | Provision the durable origin and validate backup/restore with production deployment settings |
| Cloudflare-only / Lambda-only engine | Durable cloud StateStore and event scheduler are not implemented | [PLT-5781](https://linear.app/quantum-box/issue/PLT-5781) tracks the missing backend | Implement atomic durable state and run failure/replay acceptance before claiming support |
| Certificate lifecycle | Secure CA initialization, issued-certificate expiry bounds, APNs topic checks, HTTPS key protection, and documented rotation | Synthetic certificate and loopback TLS checks | Exercise APNs/HTTPS rotation and a planned CA migration with an authorized device |
| SQLite backup / restore | Private consistent snapshots and filesystem-only restore to a new validated destination | Local backup/reopen and restore checks | Restore with the original CA/APNs material, then verify active enrollment and queued command recovery |
| Administrator UI | Same-origin static console for enrollments, commands, app/kiosk/OS/lock/erase operations, ADE, VPP, DDM, audit, and observations | Synthetic browser/API asset and mutation checks | Exercise each operation against the real-device evidence above |

Current generated enrollment profiles advertise access rights `4383`:
profile inspection, profile installation/removal, device lock, device erase,
device information, application inspection, and application management. A
database or enrollment migrated from the old profile rights `19` keeps that
recorded capability set for safety; migration does not silently grant the new
operations. Those devices must receive a new profile and complete
re-enrollment before application, kiosk, OS-update, lock, or erase operations
can be used. DDM is enabled explicitly with the `DeclarativeManagement`
command; it needs no profile capability entry.

The selected DDM declaration schemas start at iPadOS 15, while the engine's
profile-based device enrollment gate requires 16+. Supported types and status
subscription items are recorded in [ADR 0003](adr/0003-ddm.md) and [DDM usage](ddm.md).
Other Apple platforms are outside the DDM acceptance boundary. Stored OSVersion
does not attest the platform; operators select iPad targets. The per-user
enrollment expansion tracked on 2026-10-10 remains outside the M0 device-channel
scope.

## Release gates

This project is not release validated until all of these have evidence:

- Apple MDM Vendor CSR signing access and a customer-specific MDM Push
  Certificate whose topic matches the MDM payload.
- A real device completing SCEP, `Authenticate`, `TokenUpdate`, APNs wakeup,
  command delivery, and response persistence over public HTTPS.
- A supervised disposable iPad completing application install/remove, kiosk
  apply/release, OS update query/schedule, lock, and an explicitly authorized
  erase, with command responses and observations retained.
- A real Apple ADE tenant completing assigned-device synchronization, CMS
  MachineInfo bootstrap, and profile assignment, plus a real Apps & Books
  device-license event and per-device assignment check.
- Certificate rotation, revocation, backup/restore, and reverse-proxy failure
  behavior reviewed with redacted logs.
- M1 and M2 real iPad testing completed. The current workspace has no
  Apple-issued certificate, Apple ADE/Apps & Books tenant, or real iPad result,
  so these release gates remain pending and no production acceptance is claimed.
