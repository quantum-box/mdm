# Deployment

`mdmd` is distributed as one portable OCI origin process. The origin owns a
durable SQLite database, the APNs notification outbox, the enrollment CA, and
the command state machine. Keep exactly one origin process per database. A
Cloudflare Tunnel, reverse proxy, or provider gateway may scale at the edge,
but it must not create a second SQLite writer.

The container is an operational packaging option for the experimental service;
it does not turn the project into a production release or provide Apple device
acceptance evidence. The current support boundary and open M1/M2 evidence are
in the [support matrix](support-matrix.md).

## Build the image

The multi-stage [`Dockerfile`](../Dockerfile) builds `mdmd` with Rust 1.95 and
OpenSSL development headers, then copies only the release binary and the
runtime dependencies into a Debian slim image. The runtime user is UID/GID
10001. No CA, token, APNs identity, TLS key, or SQLite file is copied into the
image. `.dockerignore` excludes local credentials and build output.

Build from the repository root and pin the image in the registry before a
deployment:

```sh
docker build --pull -t registry.example/mdm:0.1.0 .
docker push registry.example/mdm:0.1.0
```

The release image is intentionally not published by this repository. A CI
workflow may build and scan it using the same Dockerfile after the software
checks pass.

The Dockerfile's default final target is the self-contained `runtime` stage,
which builds Rust in the isolated builder. CI may reuse the Linux release
binary produced by its workspace job with the `ci-runtime` target instead:

```sh
cargo build --release -p mdmd --locked
docker build --target ci-runtime -t registry.example/mdm:ci-${GITHUB_SHA} .
```

The CI target copies only `target/release/mdmd` into the same Debian Bookworm
runtime and does not compile Rust a second time. The CI Ubuntu 24.04 Linux
binary is linked against OpenSSL 3, matching the Bookworm runtime. Local
developers should use the default target when a prebuilt release binary is
unavailable.

## Filesystem and secrets

Mount `/data` on persistent local block storage. It contains `mdm.sqlite`, the
SQLite `-wal`/`-shm` files while the service is running, and optional backups.
Do not put the live database on object storage, a shared network filesystem, or
an ephemeral container layer. Keep one replica for a database. The runtime
creates missing data directories with private permissions, but the volume must
already be writable by UID/GID 10001 when the orchestrator does not copy image
ownership metadata.

The entrypoint copies configured files from secret mounts into
`/run/mdmsecrets`, applies `umask 077`, rejects symlinks and non-regular files,
limits file sizes, and sets mode 0600. Use a memory-backed mount for that
directory. It never enables shell tracing and never puts an admin or read-only
token in an `mdmd` command argument. A token supplied through an environment
secret remains an environment value because the current binary reads
`MDM_ADMIN_TOKEN` and `MDM_READ_TOKEN`; use file injection when the provider
supports it.

The supported provider-neutral variables are:

| Variable | Required | Meaning |
| --- | --- | --- |
| `MDM_PUBLIC_URL` | yes | HTTPS origin that Apple receives in the enrollment profile |
| `MDM_BOOTSTRAP_URL` / `BOOTSTRAP_URL` | no | Separate HTTPS SCEP/ADE host; defaults to `MDM_PUBLIC_URL` |
| `MDM_TOPIC` | yes | Exact `com.apple.mgmt.*` topic from the Apple MDM Push certificate |
| `MDM_ORGANIZATION` / `ORGANIZATION` | no | Profile organization; defaults to `MDM` |
| `MDM_DATABASE` / `DATABASE` | no | SQLite path; defaults to `/data/mdm.sqlite` |
| `MDM_BIND` / `BIND` | no | Listener address; defaults to `127.0.0.1:8080` |
| `MDM_CA_CERT` / `CA_CERT` | yes | SCEP/enrollment CA certificate file |
| `MDM_CA_KEY` / `CA_KEY` | yes | SCEP/enrollment CA private key file |
| `MDM_TLS_CERT` / `TLS_CERT` | no | Built-in HTTPS certificate; required with the key |
| `MDM_TLS_KEY` / `TLS_KEY` | no | Built-in HTTPS private key; required with the certificate |
| `MDM_APNS_IDENTITY` / `APNS_IDENTITY` | no | Apple MDM Push identity PEM |
| `MDM_ADMIN_TOKEN_FILE` / `ADMIN_TOKEN_FILE` | preferred | File containing the admin bearer token |
| `MDM_READ_TOKEN_FILE` / `READ_TOKEN_FILE` | no | File containing a different read-only bearer token |
| `MDM_GATEWAY_KEY_FILE` / `GATEWAY_KEY_FILE` | gateway mode | Shared key for the signed gateway adapter |
| `MDM_HEALTHCHECK_URL` | no | Health URL; plain image defaults to loopback HTTP |
| `MDM_HEALTHCHECK_CA` | no | CA bundle for an HTTPS health URL |
| `MDM_HEALTHCHECK_RESOLVE` | no | curl `host:port:address` mapping for loopback TLS |
| `MDM_SECRET_DIR` | no | Private-copy directory; defaults to `/run/mdmsecrets` |

`MDM_ADMIN_TOKEN` and `MDM_READ_TOKEN` remain supported for orchestrators that
inject secret values directly. ADE and Apps & Books files use their existing
`MDM_ADE_*` and `MDM_VPP_TOKEN_FILE` names and receive the same private-copy
treatment. The entrypoint never generates a missing CA; run the explicit
`mdmd init-ca` command once and back up the CA key separately.

Set `MDM_BOOTSTRAP_URL` when the edge requires a separate anonymous SCEP/ADE
hostname and applies mandatory client mTLS to the device hostname. Otherwise
leave it unset so the profile uses `MDM_PUBLIC_URL` for all device paths.

## Compose template

[`compose.yaml`](../compose.yaml) starts the origin without publishing a host
port. It uses built-in TLS on loopback port 8443, a persistent named volume,
and a private tmpfs for copied secrets. The optional `cloudflared` service uses
the origin's network namespace so it connects to `127.0.0.1`; enable it only
after copying [`deploy/cloudflare/config.yml.example`](../deploy/cloudflare/config.yml.example)
to `config.yml`, provisioning the tunnel credentials, and pinning
`CLOUDFLARED_IMAGE` to a reviewed tag or digest.

Prepare the local secret directory with mode 0700. Initialize the enrollment CA
explicitly before starting the origin; an operator can use the host binary or
a one-shot container with a writable output mount:

```sh
mkdir -p secrets
chmod 700 secrets
./target/release/mdmd init-ca --cert secrets/ca.pem --key secrets/ca-key.pem
chmod 600 secrets/ca-key.pem

export MDM_PUBLIC_URL=https://mdm.example.com
export MDM_TOPIC=com.apple.mgmt.EXACT_UID
export CLOUDFLARED_IMAGE=cloudflare/cloudflared:PINNED_VERSION
docker compose up -d mdmd
docker compose --profile cloudflare up -d cloudflared
```

The Compose file expects `secrets/tls.pem`, `secrets/tls-key.pem`,
`secrets/apns.pem`, `secrets/admin-token`, and `secrets/read-token`. Create
those files through the organization’s secret-management process. For a
private origin certificate, also mount the CA referenced by `caPool` in the
Tunnel configuration and set `MDM_HEALTHCHECK_CA=/run/secrets/mdm-origin-ca.pem`
when that CA is needed by the native-TLS health check. Do not commit the
directory.

For a signed Cloudflare Worker or Lambda gateway, create
`secrets/gateway-key` with a 32–128 byte printable ASCII key and use the
optional overlay. It enables `MDM_GATEWAY_KEY_FILE` while retaining the
read-only secret mount:

```sh
openssl rand -base64 48 > secrets/gateway-key
chmod 600 secrets/gateway-key
docker compose -f compose.yaml -f compose.gateway.yaml up -d mdmd
docker compose -f compose.yaml -f compose.gateway.yaml \
  --profile cloudflare up -d cloudflared
```

The Worker/Lambda `MDM_GATEWAY_KEY` secret must contain the same value. Keep
Cloudflare Access service credentials separate from this HMAC key.

Do not set `MDM_TRUST_PROXY=true` merely because traffic travels through a
Tunnel. That mode is valid only when the gateway verifies the device
certificate, strips all incoming identity headers, and signs or rewrites the
request for the local origin. A public origin that trusts arbitrary forwarded
certificate headers is an authentication bypass.

## Health, shutdown, and backup

The image health check requests `MDM_HEALTHCHECK_URL`, defaulting to
`http://127.0.0.1:8080/health` in a plain image. Native-TLS deployments must
set an `https://` URL whose certificate is trusted by the Debian system bundle,
or set `MDM_HEALTHCHECK_CA` to a mounted CA bundle. If the listener is on
loopback while the certificate uses an internal hostname, set
`MDM_HEALTHCHECK_RESOLVE` to curl's `host:port:address` form, for example
`mdm-origin.internal.example:8443:127.0.0.1`. The probe never disables TLS
verification. Compose supplies that hostname and mapping by default. `/health`
is a liveness response and does not prove that SQLite, APNs, or Apple
credentials are ready. Add provider-level readiness checks outside the
process when an orchestrator needs them. Cloudflare Tunnel metrics should be
scraped on its private metrics listener; do not publish that listener to Apple
devices.

Allow at least 30 seconds for shutdown. `mdmd` stops accepting work, drains
TLS connections for up to 15 seconds, and lets the notification worker stop.
Avoid an orchestrator hard kill during SQLite writes or APNs delivery.

Run backups from a stopped origin and keep the result encrypted outside the
live volume:

```sh
docker compose stop mdmd
docker compose run --rm --no-deps --entrypoint /usr/local/bin/mdmd mdmd \
  backup --database /data/mdm.sqlite --output /data/mdm-backup.sqlite
docker compose start mdmd
```

The backup destination must not exist. Use `mdmd restore` into a new path while
the service is stopped; it validates SQLite integrity, foreign keys, schema
version, and private-file constraints. Restore the enrollment CA, HTTPS key,
APNs identity, and provider credentials from their separately protected backup
set. A database snapshot without those keys cannot recover device identity.

## Runtime portability

The origin configuration is intentionally provider-neutral: listener address,
public URL, persistent database path, certificates, and secret-file paths are
environment/argument inputs. A provider adapter may translate edge identity
into the origin's authenticated peer and invoke the same protocol/core code.
Cloudflare and Lambda details are documented separately in
[`cloudflare.md`](cloudflare.md) and [`lambda.md`](lambda.md).

Lambda is an implemented entrypoint/gateway integration boundary. It does not
run the stateful Rust engine, SQLite, APNs worker, or live MDM listener. A
Lambda-native engine requires a durable `StateStore`, an outbox scheduler,
certificate identity translation, and an idempotent event adapter; those
requirements are outside this gateway package and must not be inferred from
the image.
