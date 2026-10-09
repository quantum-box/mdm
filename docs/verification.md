# Software verification — 2026-10-10

This report covers the local experimental implementation on
`codex/oss-apple-mdm`, using Rust 1.95.0 on macOS arm64. It is software-test
evidence, not Apple-device acceptance or a production release.

## Passed

| Check | Evidence |
| --- | --- |
| Initial MDM baseline | Before DDM changes: `cargo test --workspace --locked --quiet`, 54 passed |
| Current scoped Rust tests | Core 24, protocol 22, restore library 4, Apple fixtures 4, DDM storage 13, DDM HTTP 5, existing HTTP 7, operation HTTP 6, recovery 20, operation storage 11: **116 passed**, zero failed at final verification |
| Console behavior | `node --test crates/mdmd/tests/admin-ui.mjs`: **3 passed**; completed queries receive a fresh key, transport failures and ambiguous mutations retain the key |
| Static checks | Cached `cargo clippy --offline --workspace --all-targets --locked --no-deps -- -D warnings` passed |
| Formatting and patch checks | `cargo fmt --all -- --check` and `git diff --check` passed |
| CLI smoke | CA creation in a new private directory; server startup; enrollment profile saved at mode 0600; devices, audit, and certificate APIs; graceful shutdown; private SQLite backup with `PRAGMA integrity_check = ok` |
| Extended CLI/UI smoke | Apps/ADE/erase subcommand help, actual daemon enrollment file creation, Apple configuration flags, browser login, enrollment listing, and authenticated API rendering with temporary local credentials |
| DDM/restore CLI smoke | Actual daemon and CLI: put/list/unassign/delete declarations; schema-2 snapshot restored to a new private path, preserved deleted revision, integrity checked |
| Enrollment failure smoke | Failed HTTP enrollment removes its own partial output; existing output files are preserved |

## Remote CI evidence

GitHub Actions run [`37975531705`](https://github.com/quantum-box/mdm/actions/runs/37975531705) for commit `ce6fcd0` completed with status **Success**. Its [`rust` job](https://github.com/quantum-box/mdm/actions/runs/37975531705/job/113972753502) passed all steps defined in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

- Node.js syntax and console regression tests (`node --check` and `node --test`)
- Rust formatting (`cargo fmt --all -- --check`)
- Full locked workspace tests (`cargo test --workspace --locked`)
- Clippy with warnings denied (`cargo clippy --workspace --all-targets --locked -- -D warnings`)
- Linux release build (`cargo build --release -p mdmd --locked`)

The run provides the Linux full-suite, formatting, Clippy, and release-build evidence for this revision. It does not provide Apple-device or APNs acceptance evidence.

On this host, Cargo used `OPENSSL_DIR=/opt/homebrew/opt/openssl`. No local
release build was performed. The CI workflow includes a Linux release build,
which passed in the remote run above.

Local follow-up tests were scoped to the changed core/protocol, Apple adapter,
device operations, HTTP and DDM/restore paths. Unchanged configuration, SCEP, and native TLS suites were not repeated;
their results belong to the initial baseline. The complete workspace suite and
Linux release build are covered by the successful remote run above.

The automated tests cover protocol fixtures, enrollment/command transitions,
transaction rollback, exact SCEP replay, command idempotency, restart and lease
recovery, APNs acceptance/retry/rejection bookkeeping, NotNow, late and duplicate
responses, profile-mutation timeouts, reenrollment isolation, and revocation.
They also generate ephemeral keys for a signed/encrypted SCEP round trip and
actual loopback HTTPS tests, including anonymous bootstrap, certificate-backed
check-in, spoofed-header rejection, wrong issuers, and expired certificates.

## Remaining acceptance

No real Apple MDM Push certificate was supplied or used, no request was sent
to APNs during verification, and no physical iPad was enrolled. M1 device E2E,
M2 device recovery/release acceptance, and a minimum supported iPadOS version
therefore remain unverified. Run the [device checklist](device-test.md) using
an authorized test iPad, the correct Apple MDM Push certificate/topic, and a
reachable, trusted HTTPS origin.

DDM now implements the selected declaration schemas, generation-specific
targets, tokens/manifest/fetch/status check-in endpoints, update/delete,
management API/CLI, and atomic synchronization command/outbox persistence.
AppManaged supports iPadOS 17.2+ with explicit application rights and fresh
supervision for Required installations. The extension also covers app inventory,
App Lock prerequisites, OS updates, DeviceConfigured, confirmed erase, signed ADE
bootstrap identity binding, and durable external-operation uncertainty.
Tests cover duplicate and late reports, stale tokens, restart, full-queue
rollback, unsupported OS, unknown declaration fields, and reenrollment.
The schema-1 migration test preserves enrollment/audit rows through schema 2,
backup, restore, and reopening. Schema 3 additionally preserves observations,
ADE synchronization and license-operation state.
DDM command ACK and stored reports are not physical-device acceptance.

The missing acceptance work is tracked in this project's Linear issues:

- [PLT-5762: DDM software implementation/review](https://linear.app/quantum-box/issue/PLT-5762)
- [PLT-5763: M1 Apple certificate and real iPad E2E](https://linear.app/quantum-box/issue/PLT-5763)
- [PLT-5764: M2 real recovery, certificate rotation, restore](https://linear.app/quantum-box/issue/PLT-5764)
- [PLT-5765: M3 real DDM acceptance](https://linear.app/quantum-box/issue/PLT-5765)
- [PLT-5766: Remote CI/release verification](https://linear.app/quantum-box/issue/PLT-5766)

The additional implementation work is tracked in
[PLT-5770 (applications)](https://linear.app/quantum-box/issue/PLT-5770),
[PLT-5771 (kiosk)](https://linear.app/quantum-box/issue/PLT-5771),
[PLT-5772 (ADE)](https://linear.app/quantum-box/issue/PLT-5772),
[PLT-5773 (updates/lock/erase)](https://linear.app/quantum-box/issue/PLT-5773),
and [PLT-5774 (console)](https://linear.app/quantum-box/issue/PLT-5774).
These software changes do not close the real-device acceptance issues.
