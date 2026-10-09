# ADR 0001: Keep the MDM core stateful and protocol-independent

- Status: Accepted
- Date: 2026-10-09

## Decision

`mdm-core` owns the small state machines that describe enrollment and command
delivery. It also owns the opaque `Declaration` value used at the Apple DDM
boundary. The crate exposes data and deterministic transitions only.

The core has no HTTP client, SQL driver, queue client, certificate store, or
Apple protocol implementation. Adapters outside the crate are responsible for
transport, persistence, authentication material, and translating protocol
messages into `Reply` values.

## Enrollment transitions

`Pending` authenticates to `Authenticated`. Authentication is idempotent for
`Authenticated` and `Active`. `token_update` moves `Authenticated` to `Active`
and is idempotent for `Active`. `revoke` always produces `Revoked`; the
revoked state cannot authenticate or accept a token update.

## Command transitions

`Queued` and `Deferred` may be dispatched to `AwaitingResponse`. An
`Acknowledged` reply produces `Completed`; `Error` and `CommandFormatError`
produce `Failed`; `NotNow` produces `Deferred`. A delayed terminal response
from an earlier delivery attempt may resolve a `Deferred` command.

When a response times out, `DeviceInformation` returns to `Queued` because it
is read-only. Profile mutations become `OutcomeUnknown`, because a retry could
duplicate a device-side mutation. A late reply may resolve `OutcomeUnknown`.
Known terminal states accept only an equivalent duplicate response, and a
cancelled command cannot be changed. The storage adapter may receive a late
response for a cancelled command only when that command was previously
dispatched; it records the authenticated response and ignores it without
resurrecting the command, so the device can continue polling for newer work.
An unsolicited response for a cancelled command with no delivery attempt
remains a conflict.

## Declaration boundary

`Declaration` requires non-empty `id` and `version` values and carries its
payload as `serde_json::Value`. Apple declaration versions and server tokens
are opaque equality tokens; `same_version` requires the same identifier and
the exact same version string. The core does not parse, normalize, or order
version tokens. Protocol-specific validation belongs to a higher layer so this
crate remains usable by multiple Apple MDM transports and persistence
implementations.

## Consequences

The state transitions are easy to test without a device or a network. The
caller must persist state transitions atomically with its own delivery and
retry bookkeeping. The core cannot decide whether a credential, declaration
payload, or response is authorized; that decision belongs at the adapter
boundary.
