# ADR 0002: Transport and authentication boundaries

- Status: Accepted for the experimental device-channel service
- Date: 2026-10-09

## Decision

`mdmd` is a single-binary service with SQLite storage and built-in HTTPS as
the preferred deployment. When `--tls-cert` and `--tls-key` are configured,
the listener may bind a public address and terminates TLS itself. The built-in
TLS listener requests, but does not require, a client certificate at the
connection layer: SCEP bootstrap and bearer-authenticated operator requests may
use an anonymous TLS connection, while `/checkin` and `/mdm` require a verified
client certificate.

A separately managed TLS reverse proxy remains supported for deployments that
already centralize certificates. In that mode the application binds only to a
loopback address, uses plaintext HTTP upstream, and `--trust-proxy` must be
enabled. The two modes are mutually exclusive; configuring built-in TLS and
trusted proxy headers together is rejected.

In reverse-proxy mode, the proxy has two responsibilities that are part of
this boundary:

1. It authenticates the HTTPS server and forwards the public origin used by
   the enrollment profile.
2. It verifies the SCEP-issued client certificate for `/checkin` and `/mdm`,
   strips any client-supplied certificate headers, and writes the verified leaf
   certificate and verification result into the application headers.

The `--trust-proxy` option is therefore safe only when the proxy is local,
the upstream listener is unreachable from untrusted networks, and the proxy
rewrites both `X-MDM-Client-Verify` and `X-MDM-Client-Cert` on every request.
The application revalidates the forwarded chain against its SCEP CA, checks
the certificate validity and client-auth purpose, and maps the leaf
fingerprint to the active enrollment generation. A forwarded header by itself
is never an identity. In built-in TLS mode, the application ignores those
headers and uses the fingerprint derived from the authenticated TLS connection.

The endpoint roles are deliberately separate:

| Endpoint | Bootstrap/authentication boundary | Capability |
| --- | --- | --- |
| `/scep` | Anonymous built-in TLS or proxy HTTPS, then SCEP PKCS#7 proof of possession plus the one-time enrollment challenge | Fetch CA metadata and issue one device identity certificate |
| `/checkin` | Verified built-in TLS client certificate or verified proxy certificate, active fingerprint, matching UDID, and configured topic | Authenticate, update APNs state, or check out a device |
| `/mdm` | The same verified TLS/proxy device identity and UDID binding | Poll for one command and submit its response |
| `/v1/*` | Built-in or proxy HTTPS plus an admin or read-only bearer token | Operator enrollment, command, status, audit, and certificate metadata APIs |
| local `backup` CLI | Filesystem access to the SQLite file and output path | Create a consistent database snapshot |

SCEP is unauthenticated at the TLS layer because the device does not yet have
its MDM client certificate. The challenge is high entropy, stored only as a
hash, expires after 900 seconds, and the exact authenticated request can be
replayed to obtain its persisted response. A different request for the same
challenge and any request after revocation are rejected.

## Generation and delivery invariants

An issued client certificate belongs to exactly one enrollment row. The first
`Authenticate` for a UDID revokes the previous live row for that UDID in the
same SQLite transaction. Revocation cancels queued, deferred, awaiting, and
ambiguous commands and disables notification delivery. Every device request
checks revocation and the stored UDID before it can change state or resolve a
command.

Command dispatch, attempt numbering, and the durable outbox lease are committed
atomically before the command bytes leave the process. Notification delivery is
at-least-once: a process crash after an APNs request but before its result is
stored can cause a duplicate wake-up. A stale worker cannot overwrite a
reclaimed lease. APNs acceptance means only that Apple accepted the wake-up;
the outbox can be retried after 300 seconds until the device polls. It is not
evidence that a command ran.

Read-only information commands may return to `queued` after a response timeout.
Profile mutations become `outcome_unknown` and require reconciliation or
explicit cancellation before another mutation is sent. A cancelled or revoked
command cannot be resurrected by a late device response.

## Request and resource limits

The application caps request bodies at 2 MiB, plist input at 1 MiB, profiles at
256 KiB, and concurrent SCEP/OpenSSL work at four blocking jobs. Both the
built-in listener and a reverse proxy deployment must cap the request line and
headers, rate-limit SCEP and bearer authentication attempts, and reject
oversized query strings before they reach the application. In particular, a
base64 SCEP message in a GET query must be bounded before base64 decoding; the
body limit does not protect that path.

## Secrets and local trust

The SCEP CA key, APNs identity, HTTPS key, bearer tokens, enrollment profiles,
push tokens, database, and backups are secrets or sensitive records. Key and
database files are created with mode `0600`; the service account and its data
directory must be owned by the operator and inaccessible to other local users.
SQLite backups are plaintext snapshots and must be encrypted and access
controlled outside this process. The threat model trusts the service account
and treats a process that can replace the built-in TLS key, write the loopback
proxy, or write the service data directory as having crossed the host trust
boundary.

## Scope

The profile and routes implement the device-channel subset exercised by the
initial project: `Authenticate`, `TokenUpdate`, `CheckOut`,
`DeviceInformation`, `InstallProfile`, and `RemoveProfile`. User-channel
messages, Declarative Device Management transport, declaration synchronization,
bootstrap-token workflows, and a minimum iPadOS version are outside this ADR.
No minimum iPadOS support claim is made until a real Apple-device test records
the OS version, enrollment, APNs wake-up, command, and revocation evidence.

## Consequences

Deployment correctness depends on either the built-in TLS certificate/key
permissions or the reverse proxy configuration and its header-stripping
behavior. The server intentionally cannot protect against a privileged local
process that can read the database, replace the TLS key, or impersonate the
proxy.
Operators must treat bearer tokens and database backups as separate secrets,
and must add proxy-side rate limiting because the application does not provide
an account lockout or global request quota.
