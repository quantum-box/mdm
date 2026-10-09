# mdm

An independent Apple MDM engine written in Rust, licensed under MIT. The initial
target is the iPad device channel, covering manually enrolled devices and the
Automated Device Enrollment (ADE) bootstrap path. A single `mdmd` binary
provides the server, management API, management CLI, and administrator UI;
SQLite stores enrollment generations, commands, delivery attempts, responses,
notifications, and an audit trail.

**Experimental.** Software protocol and recovery tests are provided. No physical
iPad, Apple MDM Push certificate, or Apple ADE/Apps & Books tenant has been used
to validate this implementation. M1 (device E2E) and M2 (first OSS release
acceptance) remain open until the [device checklist](docs/device-test.md) has
evidence. Do not interpret an APNs acceptance or an HTTP 200 as successful
command execution.

## Implemented

- SCEP enrollment profiles and PKCS#7 certificate issuance using OpenSSL;
  client-certificate authentication bound to an enrollment generation.
- `Authenticate`, `TokenUpdate`, `CheckOut`, `DeviceInformation`, `InstallProfile`,
  and `RemoveProfile` with bounded plist input and explicit unsupported-channel errors.
- Application inventory and device-channel application management, supervised
  App Lock kiosk mode, ADE server-token synchronization and bootstrap,
  device-based Apps & Books (VPP) licensing, OS update queries/scheduling, and
  administrator-authorized device lock and erase. These six device-operation
  areas are exposed through the management API, CLI, and administrator UI.
- Transactional command queue and notification outbox, durable leases, APNs
  HTTP/2 transport, result correlation, deferred commands, and recovery on restart.
- Bearer-authenticated management API and CLI, optional read-only credentials,
  audit records, certificate expiry information, and validated SQLite backup/restore.
- Separate DDM declarations, generation-specific assignments, synchronization,
  and status reports, with management API and CLI operations. The selected
  iPadOS foundation still requires physical-device acceptance.

No existing MDM engine is wrapped or embedded. Redis, a message broker,
Kubernetes, Tachyon, and business/tenant management are not required.

The per-user enrollment expansion tracked on 2026-10-10 is outside this M0
device-channel scope. The [support matrix](docs/support-matrix.md) records the
implemented boundary and the evidence still required before release.

## Quick start

Rust 1.95 and OpenSSL development libraries are required to build. On Debian or
Ubuntu install `pkg-config libssl-dev`; on macOS use an existing Homebrew OpenSSL
installation and set `OPENSSL_DIR` if the build cannot discover it.

1. Build: `cargo build --release -p mdmd`.
2. Create the CA: `target/release/mdmd init-ca`.
3. Prepare the Apple **MDM** Push certificate, its matching key, and an HTTPS
   certificate for the built-in TLS listener. The [Nginx proxy](docs/nginx.conf)
   remains available when proxy termination is required.
4. Start the backend using the example below.
5. Enroll a test iPad using `mdmd enroll --output data/device.mobileconfig` and
   follow the [device checklist](docs/device-test.md).

```sh
export MDM_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MDM_API_URL="https://mdm.example.com:8443"
target/release/mdmd serve \
  --bind 0.0.0.0:8443 \
  --public-url "$MDM_API_URL" \
  --topic com.apple.mgmt.EXACT_UID \
  --tls-cert data/tls.pem \
  --tls-key data/tls-key.pem \
  --apns-identity data/apns.pem
```

The built-in listener serves HTTPS and binds to the public address only when
both TLS files are configured. It checks the device client certificate chain,
validity, and persisted fingerprint. For the reverse-proxy mode, omit the TLS
flags, keep the default loopback bind, and add `--trust-proxy`; use [the Nginx
configuration](docs/nginx.conf). Without an APNs identity, notifications
remain pending.

Optional ADE and Apps & Books credentials are loaded from private files through
`MDM_ADE_TOKEN_FILE`, `MDM_ADE_PROVIDER_CERT_FILE`,
`MDM_ADE_PROVIDER_KEY_FILE`, `MDM_ADE_DEVICE_CA_FILE`, and
`MDM_VPP_TOKEN_FILE`. See [ADE enrollment](docs/apple-enrollment.md),
[app distribution](docs/app-distribution.md), and the [device test
checklist](docs/device-test.md) for the file and permission requirements.

Profiles contain a one-time enrollment secret and must be transferred privately.
Do not publish keys, tokens, enrollment profiles, databases, or device evidence.

## Command example

```sh
target/release/mdmd command ENROLLMENT_ID \
  --idempotency-key my-device-info-request info --query DeviceName --query OSVersion
target/release/mdmd status COMMAND_ID
```

Retry the same management request with the same idempotency key when its HTTP
response is lost. Reusing the key for a different request returns a conflict.
The CLI prints generated keys before sending requests.

Commands progress through `queued`, `awaiting_response`, `deferred`, `completed`,
`failed`, `outcome_unknown`, or `cancelled`. `NotNow` waits 30 seconds. After
five minutes without a command response, information queries can be retried;
profile mutations become `outcome_unknown` and block the generation's queue.
An administrator must investigate before cancelling that unresolved command.
Cancellation means local delivery has stopped; it does not undo device execution.

## Architecture and verification

```text
crates/mdm-protocol   Apple wire types, validation, plist conversion
crates/mdm-core       Pure enrollment/command transitions and declarations
crates/mdmd          Application/storage, HTTP, identity, APNs, CLI
```

The core has no HTTP, SQL, or network dependency. Commands and notification plans
commit in one SQLite transaction. Dispatch is recorded before the HTTP reply is
sent, so a crash cannot turn a potentially executed mutation into an automatic
retry. Reenrollment revokes the former identity and isolates all old commands.

CI runs formatting, workspace tests, Clippy, and a release build. For local work,
run only checks needed for the changed crate; see [contribution guidance](CONTRIBUTING.md).
The [verification report](docs/verification.md) records local software checks,
with physical-device acceptance still open.

See [DDM usage and API](docs/ddm.md) for declaration synchronization and status.

- [Design decision](docs/adr/0001-state-and-boundaries.md) and [threat model](docs/threat-model.md)
- [Pinned Apple protocol sources](crates/mdm-protocol/docs/protocol-sources.md)
- [API and CLI operations](docs/operations.md) and [operations API reference](docs/operations-api.md)
- [Administrator UI](docs/admin.md), [ADE enrollment](docs/apple-enrollment.md), and [app distribution](docs/app-distribution.md)
- [Certificate lifecycle](docs/certificates.md) and [supported scope](docs/support-matrix.md)
- [Security reporting](SECURITY.md) and [MIT license](LICENSE)
