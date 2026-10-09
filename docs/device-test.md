# Device test

Use an isolated, disposable Apple device and a dedicated Apple MDM push
certificate. This procedure is an M1/M2 acceptance checklist, not a claim that
the repository has already passed it.

The final section adds M3 DDM acceptance. Retain redacted evidence against the
exact source revision tested.

The operator surfaces are described in [the administrator UI guide](admin.md),
[the API and CLI reference](operations-api.md), [ADE enrollment](apple-enrollment.md),
and [Apps & Books distribution](app-distribution.md).

M1 prerequisites and results are tracked in
[PLT-5763](https://linear.app/quantum-box/issue/PLT-5763), and M2 recovery in
[PLT-5764](https://linear.app/quantum-box/issue/PLT-5764).

## Prerequisites

Complete these before touching a real device:

1. Obtain Apple access to an MDM Vendor CSR Signing Certificate and create the
   customer-specific MDM Push Certificate through
   [`identity.apple.com/pushcert`](https://identity.apple.com/pushcert). An
   ordinary APNs app certificate or token key is insufficient.
2. Prepare a public DNS name and HTTPS certificate trusted by the device. The
   preferred test path uses `mdmd`'s built-in TLS listener; an existing reverse
   proxy can terminate TLS and forward the verified certificate header instead.
3. Generate the private SCEP CA and keep the CA key, APNs identity, HTTPS key,
   and admin token off the test device and out of logs.
4. Use a test iPad that can be erased and re-enrolled. Record its current
   ownership, supervision, and backup state before the test.
5. For ADE or Apps & Books acceptance, configure the Apple credentials as
   private files before starting the service. The encrypted ADE server token
   may be the `.p7m` file downloaded from Apple; the provider certificate/key
   pair is needed to decrypt it. The device CA is the Apple trust anchor used
   to verify the CMS-signed `MachineInfo` request.

   ```sh
   export MDM_ADE_TOKEN_FILE=data/ade-server-token.p7m
   export MDM_ADE_PROVIDER_CERT_FILE=data/ade-provider-cert.pem
   export MDM_ADE_PROVIDER_KEY_FILE=data/ade-provider-key.pem
   export MDM_ADE_DEVICE_CA_FILE=data/apple-device-ca.pem
   export MDM_VPP_TOKEN_FILE=data/apps-books-token
   chmod 600 data/ade-server-token.p7m data/ade-provider-cert.pem \
     data/ade-provider-key.pem data/apps-books-token
   chmod 600 data/apple-device-ca.pem
   ```

   A manually decrypted ADE token can be used by setting only
   `MDM_ADE_TOKEN_FILE`; do not configure only one provider file. Omit these
   variables when the test uses manual enrollment without Apple integrations.
   Startup validates the configured files and does not contact Apple until an
   ADE or Apps & Books operation is requested. Never commit or print their
   contents.

Apple’s device-management documentation says the device validates the MDM
service TLS certificate and uses the identity certificate from the MDM payload
for client authentication. It also requires the MDM push certificate topic to
match the profile topic. Read [Managing certificates for device management
services and devices](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices),
[MDM](https://developer.apple.com/documentation/devicemanagement/mdm), and
[Setting up push notifications for your device management
customers](https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers)
before the test.

## Start the test service

Build and initialize the service:

```sh
cargo build --release -p mdmd
mkdir -p data
chmod 700 data
./target/release/mdmd init-ca --cert data/ca.pem --key data/ca-key.pem
export MDM_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

Start the built-in TLS listener with the exact Apple MDM topic:

```sh
MDM_ADMIN_TOKEN="$MDM_ADMIN_TOKEN" \
./target/release/mdmd serve \
  --bind 0.0.0.0:8443 \
  --database data/mdm.sqlite \
  --public-url https://mdm.example.com:8443 \
  --topic com.apple.mgmt.EXACT_UID \
  --ca-cert data/ca.pem \
  --ca-key data/ca-key.pem \
  --tls-cert data/tls.pem \
  --tls-key data/tls-key.pem \
  --apns-identity data/apns.pem
```

Before installing anything, verify that the listener serves the expected HTTPS
certificate and that the configured APNs identity has the exact topic in its
certificate `UID` subject. For the Nginx alternative, omit the TLS flags, use
the default loopback bind, add `--trust-proxy`, and follow
[`docs/nginx.conf`](./nginx.conf).

When ADE is enabled, first use the API or administrator UI to synchronize the
assigned-device list, define the direct enrollment profile with an HTTPS `url`
ending in `/ade/enroll`, and assign that profile to the test serial number.
The iPad must submit Apple's CMS-signed `MachineInfo`; an unsigned serial or an
unassigned serial must be rejected. When Apps & Books is enabled, select an
asset that Apple marks device-assignable and retain the returned asynchronous
event ID for polling. See [ADE enrollment](apple-enrollment.md) and
[app distribution](app-distribution.md) for the Apple endpoint and response
semantics.

## Enroll the device

Create the one-time profile and transfer it to the test iPad:

```sh
./target/release/mdmd enroll \
  --api-url https://mdm.example.com:8443 \
  --token "$MDM_ADMIN_TOKEN" \
  --output data/device.mobileconfig
```

Install the profile using the device’s normal configuration-profile flow. The
audit API should show the sequence below. Server logs use coarse categories
only, with no private key or challenge value:

1. SCEP `GetCACert` and certificate enrollment succeed.
2. `Authenticate` arrives on `/checkin` with the expected UDID.
3. `TokenUpdate` arrives with a non-empty push token and push magic.
4. The enrollment changes to active and reports `push_ready`.

If SCEP succeeds but `Authenticate` does not arrive, stop and inspect TLS,
proxy client-certificate forwarding, the profile URLs, and the device clock.
Do not keep retrying a challenge after its 900-second lifetime.

## Send one read-only command

Use the CLI to queue a device-information command:

```sh
mdmd command <enrollment-id> info \
  --query DeviceName \
  --query OSVersion \
  --api-url https://mdm.example.com \
  --token "$MDM_ADMIN_TOKEN"
```

Verify all of the following:

- APNs accepts an MDM notification with only the `mdm` push magic field.
- The device connects to `/mdm` over HTTPS with its identity certificate.
- The command response includes the matching command UUID and reaches
  `acknowledged`/`completed` state.
- `mdmd audit` records enrollment, notification, dispatch, and response events.

## Test applications, kiosk, OS updates, lock, and erase

Use a supervised, disposable iPad enrolled with a new profile. Confirm that
the downloaded MDM payload advertises access rights `4383`. A migrated
enrollment whose stored profile rights are `19` must be re-enrolled before this
section; do not upgrade its rights in place.

Run the application checks in this order:

1. Request `InstalledApplicationList` and `ManagedApplicationList`, then retain
   the returned inventory and the command IDs as the baseline.
2. Install one device-based App Store app and one Enterprise app whose
   `ManifestURL` is an HTTPS URL reachable by the iPad. For an Apps & Books
   test, associate a device-assignable asset first and poll Apple's event to a
   terminal state. Queue the MDM install only after the license operation is
   accepted, then use a fresh managed-application observation to verify the
   app reached the expected state.
3. Remove the test apps and verify the corresponding observation. A server
   ACK, Apple event acceptance, or HTTP 200 alone does not prove installation
   or removal.

For kiosk mode, confirm `IsSupervised` and a completed installed-application
observation for the selected bundle ID. Apply the kiosk policy through the
administrator UI, API, or CLI, verify that the iPad is restricted to the app,
then release the policy and verify normal use is restored. The service must
reject a kiosk request when supervision or fresh app evidence is missing.

For OS updates, request the available-update and update-status views first.
Schedule one supported update with an explicit product version and policy,
record the device response and reboot, and verify the resulting version with a
new Device Information observation. Treat a timeout as an unknown mutation and
do not schedule another update until the device state is reconciled.

For a lock test, send `DeviceLock`, verify the screen is locked on the iPad,
and retain the command response and audit entry. For an erase test, use only a
disposable device whose owner has explicitly authorized erasure: prepare the
server-side erase intent, compare the displayed serial number, confirm the
intent with an administrator token, and verify the device reaches the erase
flow. Never make erase an automatic recovery action or run it against a
production or personally owned device.

Repeat one read-only observation and one mutation through `/admin` to verify
that the administrator UI shows queued, ACK, observed, and outcome-unknown
states without treating ACK as device completion. The UI token is held in
browser memory only; retain redacted audit evidence rather than screenshots
containing tokens, serials, UDIDs, or certificates.

## Test profile mutation and recovery

Only continue after the read-only command passes. Use a harmless, disposable
configuration profile for the install test:

```sh
mdmd command <enrollment-id> install \
  --profile data/test-profile.mobileconfig \
  --api-url https://mdm.example.com \
  --token "$MDM_ADMIN_TOKEN"
mdmd status <command-id> --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
```

Remove the same profile by its payload identifier:

```sh
mdmd command <enrollment-id> remove \
  --identifier com.example.test-profile \
  --api-url https://mdm.example.com \
  --token "$MDM_ADMIN_TOKEN"
```

Do not retry an `outcome_unknown` mutation until its device-side result is
known. The engine waits 300 seconds for an ordinary response; a `NotNow`
response waits 30 seconds before another attempt.

## Revoke and record evidence

After the test, revoke the enrollment and verify that queued work is cancelled:

```sh
mdmd revoke <enrollment-id> --api-url https://mdm.example.com --token "$MDM_ADMIN_TOKEN"
mdmd devices --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
mdmd audit --api-url https://mdm.example.com --token "$MDM_READ_TOKEN"
```

Record the OS version, device model, certificate fingerprints, timestamps,
command IDs, final states, and redacted audit output. Never include UDIDs,
push tokens, client certificates, private keys, or enrollment challenges in a
public issue.

## Verify backup and certificate recovery

Use a stopped test instance and a copy of the database after the device has
become active:

```sh
mdmd backup --database data/mdm.sqlite --output data/mdm-backup.sqlite
mdmd restore --backup data/mdm-backup.sqlite --database data/mdm-restored.sqlite
```

Verify that the restore destination was new and mode `0600`, then start an
isolated service with the restored database, the original SCEP CA certificate
and key, the same APNs topic and identity, and the staged HTTPS certificate.
Confirm that the enrollment remains active, its certificate fingerprint and
expiry are unchanged, queued notification state is present, and a read-only
device-information command can complete. Do not point two running instances
at the same database or send commands from both instances.

For rotation evidence, stage a replacement HTTPS certificate with the same
hostname and a replacement APNs identity with the same `UID` topic. Restart
the service, verify `/health`, `/v1/certificates`, and one APNs wake-up, then
retain the previous files until rollback is no longer needed. A SCEP CA
replacement is a separate migration: it requires new profiles and device
re-enrollment, and is outside this no-renewal acceptance path.

## Blocked test states

Local synthetic tests can run without Apple-issued material. M1 and M2 real
iPad testing is blocked until the Apple MDM Push Certificate, matching topic,
public TLS certificate, reachable APNs path, and (for those lanes) Apple ADE or
Apps & Books credentials are available. A successful local SCEP, ADE fixture,
VPP fixture, or HTTP test does not establish Apple enrollment or application
acceptance. No production acceptance is claimed until the real-device and
Apple-tenant evidence above is attached to the tested source revision.

## M3 DDM acceptance

Use a profile-enrolled iPad running iPadOS 16+. Follow [DDM usage](ddm.md) to
create a status subscription and its simple activation. Record actual OS,
enrollment method, and supervision; a stored OSVersion is not platform evidence.

1. Enable DDM. Observe its APNs wakeup, command delivery, ACK, token request,
   manifest, and individual declaration fetches as separate events.
2. Assign the subscription and activation to the same enrollment generation.
   Verify `management.declarations` reports valid/active identifiers and matching
   tokens. Confirm a subscribed device status arrives through the status API.
3. Change subscription content with a fresh ServerToken. Observe manifest-token
   change, new fetches, and status. Unassign/delete and verify removal and 404.
4. Install/remove a harmless traditional profile during DDM use. Confirm that
   the selected declarations do not claim its settings or change queue semantics.
5. Reenroll, then verify old certificate/targets cannot serve the new generation.
   Explicitly enable and assign the new generation; retain redacted reports.

For failure acceptance, interrupt the daemon after an edit commits and before
notification. Confirm the same persisted synchronization intent resumes.
Preserve duplicate and late reports without treating server receipt time as
device execution order. `FullReport` remains visible to the consumer.
Attach real evidence to [PLT-5765](https://linear.app/quantum-box/issue/PLT-5765).
Synthetic HTTP requests and local schema tests do not complete this gate.
