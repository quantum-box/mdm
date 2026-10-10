# MDM service and core threat model

`mdm-core` is a pure domain boundary. It does not receive network input
directly, store secrets, or contact Apple devices. Its threat model therefore
focuses on how callers use the state transitions and opaque declaration data.
The `mdmd` service adds the transport, identity, persistence, APNs, and local
operator boundaries described below. The service is experimental and has no
real-device acceptance claim.

## Assets

- Enrollment lifecycle and revocation state.
- Declaration identifiers, versions, and payloads.
- Command delivery outcome, especially whether a profile mutation may have run.
- The integrity of retry and cancellation decisions.
- Enrollment challenges, device certificates, APNs device tokens, push magic,
  management tokens, configuration profiles, and SQLite backups.
- Gateway signing keys and provider-to-origin service credentials.

## Trust boundaries

1. An HTTP or protocol adapter converts authenticated device messages into
   `Reply` values and command kinds.
2. A persistence adapter stores enrollment, declarations, and command state.
3. An operator or API caller chooses which declaration or command is queued.

The core trusts callers to authenticate and authorize those inputs. It only
enforces local invariants and does not treat a JSON payload as a validated
Apple declaration. The service adds these boundaries:

4. Public HTTPS terminates either in the built-in TLS listener or at a reverse
   proxy. Built-in TLS derives an optional authenticated peer fingerprint from
   the connection; proxy mode trusts device-certificate headers only when the
   local proxy is configured to overwrite them. Signed gateway mode instead
   authenticates an HMAC envelope over the method, raw path/query, exact body,
   device certificate, timestamp, and nonce. The gateway attests the public
   device TLS connection; origin TLS authenticates a separate transport peer.
5. SCEP bootstrap uses a one-time challenge and a signed/encrypted PKCS#7
   request; `/checkin` and `/mdm` require an active SCEP-issued certificate
   whose fingerprint and UDID match the current enrollment generation.
6. Operator endpoints use bearer tokens. The local backup command uses
   filesystem authority rather than the HTTP token and writes a plaintext
   SQLite snapshot.

## Main threats and controls

| Threat | Control in `mdm-core` | Required control outside the crate |
| --- | --- | --- |
| Revoked enrollment is reused | `authenticate` and `token_update` reject `Revoked`; `revoke` is idempotent | Persist revocation durably and check it before sending |
| A mutation is sent twice after timeout | Mutating command kinds become `OutcomeUnknown` instead of returning to `Queued` | Correlate command identifiers and resolve ambiguous outcomes before retry |
| A late response changes a known result | Known terminal states accept only equivalent duplicate replies; a response for a previously dispatched cancelled command is recorded and ignored without changing state | Authenticate the response and bind it to the command/device; reject responses for cancelled commands with no delivery attempt |
| Malformed or untrusted declaration content is accepted as safe | `Declaration` validates only non-empty identity fields and preserves payload opacity | Validate schema, signature, authorization, and payload limits at the protocol/API boundary |
| State is lost between delivery and persistence | Core transitions are deterministic and side-effect free | Commit state and delivery attempt records atomically or use a durable outbox |
| Sensitive payloads leak through logs | Core has no logging or transport behavior | Redact payloads and credentials in adapters, traces, and error reporting |
| A public caller forges device identity headers | Core has no transport assumptions | Prefer built-in TLS, which ignores forwarded headers and derives the peer fingerprint from the connection; otherwise bind the application to loopback, require a proxy that strips and rewrites certificate headers, and revalidate the complete chain in `mdmd` |
| A stale certificate or old enrollment generation changes state | Core rejects revoked transitions | Persist the leaf fingerprint and UDID binding, revoke the prior live generation atomically on re-enrollment, and check revocation before every device operation |
| APNs accepts a wake-up but the device never polls | Core separates dispatch from command result | Use a leased durable outbox, retry accepted notifications after 300 seconds, and never treat APNs HTTP 200 as command execution |
| A lost response causes a profile mutation to run twice | Core maps mutation timeout to `OutcomeUnknown` | Persist delivery attempts atomically, block the generation queue, and require reconciliation or explicit cancellation |
| SCEP parsing consumes excessive CPU or memory | Core has no parser or resource limit | Cap body and query input before decoding, bound blocking OpenSSL work, and rate-limit SCEP at the proxy |
| Bearer token guessing or accidental disclosure | Core has no credential store | Use high-entropy tokens over HTTPS, keep them out of logs, and add proxy-side rate limiting; tokens remain transient plaintext in the service process |
| Database, WAL, or backup contents expose enrollment secrets | Core never persists data | Restrict the service account and data directory, verify database sidecar permissions, protect the built-in TLS key, and encrypt plaintext backups at rest |
| Enrollment profile generation fails after a row is created | Core has no enrollment API | Validate all profile inputs before persistence or roll back/delete the pending row on generation failure |
| An edge request is changed or replayed | Core has no gateway assumptions | Verify the shared canonical HMAC before certificate parsing, enforce a 30-second clock window, and atomically persist the nonce through its complete validity window, including restart |
| A caller forwards another device's certificate | Core has no TLS verifier | The Worker uses verified, unrevoked Cloudflare certificate metadata; Lambda uses API Gateway's authenticated event context. Strip caller identity headers, verify the signed leaf's CA/purpose/expiry again at the origin, and bind it to the live enrollment generation |
| The origin TLS peer is confused with the device peer | Core has no transport identity | The signed gateway overwrites the native origin peer extension, including an explicit anonymous peer for bootstrap. Legacy trusted-proxy mode and gateway mode are mutually exclusive |
| The gateway leaks credentials or exhausts origin resources | Core has no edge runtime | Use a fixed verified HTTPS origin, separate Access credentials from the HMAC key, reject redirects, forward once, and bound request/response bytes and the complete response deadline |
| Bootstrap is blocked by host-wide mTLS | Core has no host routing | Use a separate HTTPS SCEP/ADE bootstrap origin while keeping `/checkin` and `/mdm` on the certificate-authenticated device origin |
| An ephemeral cloud instance loses enrollment or delivery state | Core only returns transitions | Keep the current Rust origin and SQLite WAL on a persistent block volume; Cloudflare/Lambda adapters own no command state. Async outbox ports preserve atomic lease/result semantics for future durable backends |

## Residual risks

`OutcomeUnknown` is intentionally conservative: it protects against an
unobserved device-side mutation but requires an external reconciliation path.
`cancel` only changes local command state; it cannot undo a command already
accepted by a device. A late response for a dispatched cancelled command is
retained in response history and audit records but cannot reopen the command.
`Declaration::same_version` checks only same-identifier,
exact-token equality; it does not prove that a declaration is compatible,
signed, or safe to install. The service stores push tokens, command payloads,
and response material in SQLite; database backups are plaintext unless the
operator encrypts them. Built-in TLS is the preferred single-binary transport;
the reverse proxy and its rate limits remain supported deployment
responsibilities. No minimum iPadOS version or DDM capability is claimed.

A gateway signing key is authority to attest a device peer, so protect and
rotate it like an authentication credential. Operator bearer tokens are still
required for management endpoints. Origin Access/network policy must prevent
bypassing the edge; the gateway-local `/health` response reports only gateway
liveness. The origin's unsigned loopback health exception can also see a local
reverse proxy as its peer and must remain behind that private origin policy.
No Cloudflare/AWS account deployment or real-device validation is implied by
the synthetic gateway tests. See [ADR 0005](adr/0005-deployment-boundaries.md).
