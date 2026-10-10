# Operations

This service is an initial experimental MDM engine. The operational contract
below describes the current intended CLI and HTTP surface; it is not a
production SLO or a claim of Apple-device acceptance.

## Process and trust boundary

Run one `mdmd` process per database. It opens the SQLite database with private
permissions. The preferred mode uses `--tls-cert` and `--tls-key` to serve
public HTTPS directly; plaintext mode is restricted to the loopback default
and expects a TLS reverse proxy to handle public HTTPS and client-certificate
verification. The device-facing paths are `/scep`, `/checkin`, and `/mdm`; the
management API is under `/v1`.

Use the built-in listener for a standalone deployment:

```sh
mdmd serve --bind 0.0.0.0:8443 \
  --public-url https://mdm.example.com:8443 \
  --tls-cert data/tls.pem --tls-key data/tls-key.pem \
  --topic com.apple.mgmt.EXACT_UID --apns-identity data/apns.pem
```

For Nginx or another terminating proxy, omit the TLS flags, keep the default
loopback bind, and add `--trust-proxy`.

The SCEP CA key, Apple MDM push identity, HTTPS private key, admin token, and
read token are secrets. Keep them outside the repository and out of logs. In
proxy mode, the reverse proxy must pass only a verified client certificate to
the service when `--trust-proxy` is enabled. Built-in TLS derives the peer
identity from the TLS connection and ignores proxy certificate headers.

SCEP `PKIOperation` requests sent with GET use a maximum 16 KiB encoded
`message` query value. POST `PKIOperation` requests accept up to 1 MiB of DER
body data; larger requests are rejected before OpenSSL parsing.

## Authentication roles

Send `Authorization: Bearer <token>` on management API requests.

| Role | Source | Allowed actions |
| --- | --- | --- |
| Admin | `MDM_ADMIN_TOKEN` | Enrollment creation, command enqueue/cancel, revocation, and all HTTP reads |
| Read-only | `MDM_READ_TOKEN` | `GET` endpoints only |
| Device | SCEP-issued client identity | `/checkin` and `/mdm` for its own enrollment |
| Local operator | Filesystem access | The `backup` and `restore` CLI commands; they do not call the HTTP API or consume a bearer token |

Admin and read-only tokens must be different and at least 32 characters long.

## Enrollment lifecycle

1. `POST /v1/enrollments` creates a pending enrollment, stores only a hash of
   its challenge, and returns the enrollment ID plus the XML profile. The
   challenge is valid for 900 seconds.
2. The device installs the profile, requests its identity through SCEP, and
   sends `Authenticate` followed by `TokenUpdate` to `/checkin`.
3. The service binds the device UDID to the issued certificate fingerprint and
   stores the APNs token and push magic from `TokenUpdate`.
4. Queued commands are notified through APNs. The device polls `/mdm`, receives
   one command at a time, and returns a response with the matching command UUID.
5. `POST /v1/enrollments/:id/revoke` revokes the enrollment, clears push state,
   and cancels commands that have not reached a known terminal result.

The enrollment profile is device-channel only. User-channel check-ins and
Declarative Device Management capabilities are deliberately outside the
initial release; see [`support-matrix.md`](./support-matrix.md).

## Management API

All request and response bodies are JSON except the `profile` string returned
by enrollment creation, which contains XML plist bytes escaped as a JSON
string.

### Enrollments

```text
POST /v1/enrollments
Content-Type: application/json
Authorization: Bearer $MDM_ADMIN_TOKEN
{}
```

The response contains `id` and `profile`:

```json
{
  "id": "<enrollment-id>",
  "profile": "<?xml version=\"1.0\" ..."
}
```

List enrollments with a lexicographic cursor:

```text
GET /v1/enrollments?after=<id>
Authorization: Bearer $MDM_READ_TOKEN
```

Revoke an enrollment:

```text
POST /v1/enrollments/<enrollment-id>/revoke
Authorization: Bearer $MDM_ADMIN_TOKEN
```

### Commands

Enqueue one command with an idempotency key:

```text
POST /v1/enrollments/<enrollment-id>/commands
Content-Type: application/json
Authorization: Bearer $MDM_ADMIN_TOKEN
```

Device information:

```json
{
  "idempotency_key": "inventory-2026-10-09-001",
  "command": {
    "type": "device_information",
    "queries": ["DeviceName", "OSVersion", "SerialNumber"]
  }
}
```

The other supported command types are `install_profile` with the profile bytes
and `remove_profile` with a profile identifier. Use the CLI for profile
installation so its request encoding stays aligned with the server:

`mdm-protocol` accepts XML configuration profiles up to 256 KiB. The
management router accepts request bodies up to 2 MiB, leaving room for JSON
and byte-array encoding around a profile.

```sh
mdmd command <enrollment-id> install --profile data/profile.mobileconfig \
  --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd command <enrollment-id> remove --identifier com.example.profile \
  --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
```

Reuse of an idempotency key with the same enrollment and payload returns the
original command ID. Reuse with a different payload is a conflict.

Inspect or cancel a command:

```text
GET  /v1/commands/<command-id>
POST /v1/commands/<command-id>/cancel
```

Cancellation changes local delivery state. It cannot undo a command already
accepted by a device.

### Audit and certificates

```text
GET /v1/audit?after=0
GET /v1/certificates
```

Use the audit cursor after every operational review. Certificate output is
metadata and issued-certificate material needed for diagnosis; do not copy it
into logs or tickets without redaction.

## Retry and failure semantics

- A `NotNow` device response defers the command for 30 seconds.
- A response timeout is 300 seconds. A read-only `DeviceInformation` command
  returns to the queue; `InstallProfile` and `RemoveProfile` become
  `outcome_unknown` because a retry could repeat a device-side mutation.
- An exact SCEP request replay receives the previously persisted response. A
  different request for the same one-time challenge is rejected.
- An APNs-accepted notification remains eligible for a repush after 300 seconds
  when the device has not polled. This covers a push accepted by APNs without
  treating it as proof that the device woke up.
- APNs transport failures and HTTP 403 responses are retried with bounded
  backoff and remain pending. Check the MDM push certificate topic and expiry;
  after renewing the certificate, replace `data/apns.pem` and restart `mdmd` so
  the worker loads the new identity. Other permanent APNs rejections leave the
  notification rejected and record a short reason.
- A device `Check Out` or an admin revocation cancels pending delivery and
  prevents subsequent device use of the enrollment.
- Cancelling a command after dispatch does not claim that the device did not
  execute it. A late response from the still-authenticated device is retained
  in response history and audit records, ignored for state transition, and
  does not prevent the next queued command from being returned. A response
  for a command that was never dispatched is rejected.

When a mutation is `outcome_unknown`, inspect the device and command result
before deciding whether to enqueue a new mutation. Do not use timeout as proof
that the device did not apply the command.

## CLI runbook

Use the API URL and token on each CLI invocation:

```sh
mdmd enroll --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN" --output data/device.mobileconfig
mdmd devices --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
mdmd command <enrollment-id> info --query DeviceName --query OSVersion --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd command <enrollment-id> install --profile data/profile.mobileconfig --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd command <enrollment-id> remove --identifier com.example.profile --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd status <command-id> --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
mdmd revoke <enrollment-id> --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd cancel <command-id> --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd audit --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
mdmd certificates --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
```

Run backups exclusively from the CLI while the server is stopped. This command
uses filesystem access to the database and does not use `MDM_ADMIN_TOKEN`:

```sh
mdmd backup --database data/mdm.sqlite --output data/mdm-backup.sqlite
chmod 600 data/mdm-backup.sqlite
```

The backup destination must not already exist. Copy the database and keys
together only through an encrypted, access-controlled channel.

Restore into a new path while the service is stopped. The restore helper checks
that the source is a private regular file, passes SQLite integrity and foreign
key checks, uses the supported schema version, and never overwrites the
destination:

```sh
mdmd restore --backup data/mdm-backup.sqlite --database data/mdm-restored.sqlite
chmod 600 data/mdm-restored.sqlite
```

Keep the original SCEP CA certificate and private key with the restored
database. Startup rejects a mismatched CA key, and using a different CA would
leave the stored enrollment fingerprints and device trust chain unusable.
Restore the APNs identity with the same topic and the HTTPS certificate/key
pair before starting the service. Start the restored instance in an isolated
directory first, inspect `/v1/certificates` and the audit cursor, and only then
replace the production database path. Remove a temporary restore securely
after verification.

The service does not provide an automatic SCEP renewal endpoint. Keep the
current CA for existing devices; a CA replacement is a planned migration that
requires new enrollment profiles and device re-enrollment. APNs and HTTPS
certificates can be rotated independently when their topic, hostname, and
trust requirements remain unchanged.

For the persistent OCI layout, secret-file handling, shutdown grace period,
and encrypted backup runbook, see [Deployment](deployment.md). The Cloudflare
edge and Lambda gateway boundaries are documented in
[cloudflare.md](cloudflare.md) and [lambda.md](lambda.md); they do not make an
ephemeral database suitable for the stateful origin.

## Declarative management

Use [DDM operations](ddm.md) for enablement, declaration revisions, assignments,
and status observation APIs. These operations use the same administrator/read
roles and audit contract as commands. Keep `outcome_unknown` synchronization
results under investigation; an APNs success or command ACK is not declaration
application evidence. Schema 1 databases migrate transactionally to schema 2
on startup; restore validates both versions and migrates 1 on the next start.

## Deployment status

The project currently has no production deployment, Apple-issued credential
set, real-device acceptance report, or release support commitment. Keep this
statement current when the first complete iPad test is documented.

Application, kiosk, OS update, ADE, Apps & Books and confirmed-erase endpoints
are described in [Extended device operations](operations-api.md).
