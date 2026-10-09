# Contributing

This repository is an experimental MIT-licensed Apple MDM implementation. A
contribution should make its protocol boundary, security assumptions, and
validation evidence easy to review.

## Before opening a change

Read the [state and boundaries ADR](./docs/adr/0001-state-and-boundaries.md),
[threat model](./docs/threat-model.md), and [support matrix](./docs/support-matrix.md).
Keep the following boundaries intact:

- `mdm-core` contains protocol-independent state transitions and opaque DDM
  declaration data.
- `mdm-protocol` parses and emits bounded Apple device-channel messages.
- `mdmd` owns HTTP, SCEP, APNs, persistence, and the CLI.
- User-channel and DDM additions require an explicit design update; do not
  silently broaden the initial device-channel profile.

## Local checks

The Rust checks can be expensive. Run the narrowest relevant check locally and
leave the full workspace checks to CI when the change is larger:

```sh
cargo fmt --all -- --check
cargo test -p mdm-protocol
```

For console changes, run `node --test crates/mdmd/tests/admin-ui.mjs`
without compiling Rust.

For changes under `mdmd`, run the focused package tests when practical. CI
runs the complete workspace test, clippy, and release build:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mdmd
```

Do not run a real Apple-device test with production credentials from an
ordinary pull request. Use the gated procedure in
[`docs/device-test.md`](./docs/device-test.md) and publish only redacted
evidence.

## Security and privacy

Never commit SCEP CA keys, APNs identities, HTTPS keys, management tokens,
device identity certificates, push tokens, enrollment challenges, or raw MDM
responses. Keep test artifacts under ignored `data/` paths and scrub UDIDs
and certificate material from logs and issues.

Changes that affect TLS termination, client-certificate forwarding, SCEP
authentication, APNs topic binding, enrollment revocation, command retries, or
backup behavior need a threat-model update and a focused test.

## Pull requests

Describe the resulting behavior, the affected trust boundary, and the checks
you ran. State clearly when a check is synthetic or CI-only. Do not describe a
local fixture or a passing build as Apple-device acceptance.
