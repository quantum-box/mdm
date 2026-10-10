# ADR 0005: Portable origin and provider gateway boundary

- Status: Accepted for the experimental deployment package
- Date: 2026-10-10
- License: MIT

## Context

The MDM engine needs a durable SQLite state machine, an APNs notification
worker, and a device TLS/check-in listener. Operators also need a portable
deployment artifact and may place a Cloudflare, AWS, or other HTTP gateway in
front of it. A provider gateway can terminate public TLS and change the
transport identity boundary; an ephemeral function runtime cannot safely own
the current SQLite and outbox state.

## Decision

The canonical deployment is one `mdmd` OCI container with a persistent `/data`
volume and one process per SQLite database. The image is built by the
multi-stage root `Dockerfile` and runs as UID/GID 10001. A private tmpfs at
`/run/mdmsecrets` receives copies of mounted credentials. The entrypoint uses
`umask 077`, rejects symlinks and non-regular files, enforces size limits, and
never places administrator or read-only tokens in `mdmd` arguments. It never
initializes an enrollment CA automatically; `mdmd init-ca` remains an explicit
operator action.

Runtime inputs use provider-neutral environment names for the public URL,
topic, organization, database, bind address, CA, HTTPS, APNs, operator tokens,
and optional gateway HMAC key. Provider-specific adapters may populate those
inputs, but the protocol crate does not contain Cloudflare or Lambda branches.

Notification delivery is also provider-neutral. `Clock`, `NotificationStore`,
and `PushProvider` are the worker ports, and bounded `worker::tick` recovers
expired leases and processes at most one notification per invocation. The
standalone host uses a two-second interval adapter; a queue, Lambda invocation,
or external scheduler can call the bounded tick without embedding a daemon
loop in the provider adapter.

Cloudflare is an edge adapter. A standard HTTP Tunnel does not preserve the
Apple client TLS certificate to the origin, so a deployment must either use
native origin TLS directly, a true L4 TLS passthrough service, or a reviewed
edge mTLS gateway. The gateway must allow anonymous `/scep` bootstrap and
require a validated device certificate for `/checkin` and `/mdm`. Certificate
forwarding is signed and authenticated separately from Cloudflare Access
service authentication; a forwarded header alone is never trusted. The
Worker-to-origin connection uses a fixed HTTPS hostname and certificate
verification with `noTLSVerify: false`.

The repository includes a Lambda HTTP API v2 gateway adapter. It translates
API Gateway mTLS events into the common authenticated peer and calls the
durable origin. It does not host SQLite, the APNs worker, or the live MDM
listener. An ALB event adapter and a Lambda-native engine are outside the
gateway package and require their own state and transport contracts.

Shutdown allows at least 30 seconds so the origin can drain TLS and stop its
worker. Backups run while the origin is stopped, produce a new private SQLite
file, and are encrypted and stored separately from the live volume and key
material.

## Consequences

The same Rust origin image can run on a VM, container platform, or persistent
block-volume service. Cloudflare and Lambda adapters can be changed without
changing Apple plist or command types. The SQLite single-writer
constraint limits horizontal origin scaling; high availability requires a
future storage and outbox design rather than multiple containers sharing the
file.

Standard Cloudflare Tunnel deployment remains conditional on an edge mTLS plan
and a path-specific SCEP policy. A Lambda-native origin is outside this
package. Neither edge adapter supplies physical Apple-device acceptance
evidence.

The fully serverless StateStore/outbox direction is tracked in
[PLT-5781](https://linear.app/quantum-box/issue/PLT-5781).

## References

- [Cloudflare Tunnel origin protocols](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/)
- [Cloudflare origin parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
- [Cloudflare BYOCA](https://developers.cloudflare.com/ssl/client-certificates/byo-ca/)
- [Cloudflare certificate forwarding](https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/)
- [AWS API Gateway HTTP API mTLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)
- [AWS Lambda ephemeral storage](https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html)
