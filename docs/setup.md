# Setup

This repository is an experimental, MIT-licensed Apple MDM implementation. It
is suitable for local protocol and API work. It has not been validated for a
production rollout or against a real Apple device; see the
[support matrix](./support-matrix.md) before treating any result as an
acceptance result.

## Build

Use a recent macOS or Linux host with Rust 1.95.0 from
[`rust-toolchain.toml`](../rust-toolchain.toml). On Debian or Ubuntu, install
OpenSSL build dependencies first:

```sh
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev
```

Build the single server and CLI binary:

```sh
cargo build --release -p mdmd
```

The binary is `target/release/mdmd`.

## Apple credentials and certificates

The three certificate roles below are separate:

| Material | Used for | How it is obtained |
| --- | --- | --- |
| SCEP CA (`data/ca.pem`, `data/ca-key.pem`) | Signs per-enrollment device identity certificates | Generated locally by `mdmd init-ca`; keep the private key secret |
| HTTPS server certificate | Lets an Apple device establish TLS with the MDM service | Issued by a CA trusted by the device, or paired with a root certificate in the profile |
| Apple MDM push identity (`data/apns.pem`) | Authenticates MDM push notifications to APNs | Created through Apple’s MDM vendor CSR and Push Certificates Portal flow |

An ordinary app APNs certificate, an APNs token key, or a development push
identity is not an MDM push identity. Apple’s MDM profile requires the APNs
certificate subject to match the configured `com.apple.mgmt.*` topic, and Apple
documents that device management uses certificate based push rather than the
token based push process.

The Apple prerequisite is an MDM Vendor CSR Signing Certificate. Apple says
that this certificate is used to sign a customer CSR and generate an MDM Push
Certificate at `identity.apple.com`. Account Holders request access from Apple:

- [Requesting access to an MDM Vendor CSR Signing Certificate](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate)
- [Setting up push notifications for your device management customers](https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers)

The customer then uploads the signed CSR at
[`identity.apple.com/pushcert`](https://identity.apple.com/pushcert) and returns
the resulting MDM certificate to the service operator. Keep the private key
that created the CSR with the customer service instance.

Apple also requires a valid HTTPS service certificate. If the service uses an
organization root that the device does not already trust, include the root and
intermediates in the same profile as the MDM payload. The repository’s SCEP CA
is a separate enrollment CA and does not replace the public HTTPS certificate.
See [Managing certificates for device management services and devices](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices).

## Initialize the local SCEP CA

Create a private data directory and generate the CA once. The command refuses
to overwrite either output path:

```sh
mkdir -p data
chmod 700 data
./target/release/mdmd init-ca \
  --cert data/ca.pem \
  --key data/ca-key.pem
chmod 600 data/ca-key.pem
```

Do not commit `data/ca-key.pem`, the APNs identity, or management tokens. The
default `.gitignore` excludes the `data/` directory.

## Start the service with built-in TLS

The preferred standalone mode terminates HTTPS in `mdmd` and binds directly to
the public address. Provide the server certificate and matching private key
together; the listener requests device client certificates and passes the
verified peer identity to the device-channel handlers. Start the service with
an admin token of at least 32 characters:

```sh
export MDM_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MDM_READ_TOKEN="$(openssl rand -hex 32)"

MDM_ADMIN_TOKEN="$MDM_ADMIN_TOKEN" \
MDM_READ_TOKEN="$MDM_READ_TOKEN" \
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

Replace `com.apple.mgmt.EXACT_UID` with the exact topic in the Apple MDM push
certificate. The certificate chain in `data/tls.pem` must be trusted by the
device. Do not reuse the enrollment SCEP CA as the public HTTPS certificate
unless the device trusts that CA.

## Alternative: terminate TLS in Nginx

Keep `mdmd` on its default loopback listener when an existing reverse proxy
owns the public address. Omit `--tls-cert` and `--tls-key`, and add
`--trust-proxy` so only headers overwritten by the local proxy are accepted:

```sh
./target/release/mdmd serve \
  --database data/mdm.sqlite \
  --public-url https://mdm.example.com \
  --topic com.apple.mgmt.EXACT_UID \
  --ca-cert data/ca.pem \
  --ca-key data/ca-key.pem \
  --apns-identity data/apns.pem \
  --trust-proxy
```

Use [`docs/nginx.conf`](./nginx.conf) as the reference proxy configuration.

## Create an enrollment profile

With the server running, use the admin token to create an enrollment and write
the returned XML profile:

```sh
./target/release/mdmd enroll \
  --api-url https://mdm.example.com:8443 \
  --token "$MDM_ADMIN_TOKEN" \
  --output data/device.mobileconfig
```

The profile contains a short-lived enrollment challenge. Treat it as a secret
until the device has installed the profile. The challenge expires after 900
seconds and is consumed by the first valid SCEP enrollment.

The SCEP GET `PKIOperation` query is limited to a 16 KiB encoded message. Use
POST for larger requests, up to the 1 MiB DER request limit.

For a real-device attempt, install `data/device.mobileconfig` on an isolated
test device only. Follow the acceptance sequence in
[`device-test.md`](./device-test.md).

## Read-only access

Set `MDM_READ_TOKEN` to a different token when operators need read-only access.
Use it for `GET` commands such as `mdmd devices`, `mdmd status`, `mdmd audit`,
and `mdmd certificates`. Keep `MDM_ADMIN_TOKEN` for enrollment creation,
command enqueue, cancellation, revocation, and database backup.

## Official protocol references

The implementation’s pinned Apple schema release and exact MDM profile fields
are recorded in [`mdm-protocol/docs/protocol-sources.md`](../crates/mdm-protocol/docs/protocol-sources.md).
The main Apple references are [MDM](https://developer.apple.com/documentation/devicemanagement/mdm),
[Check-in](https://developer.apple.com/documentation/devicemanagement/check-in/),
and [Sending MDM commands to a device](https://developer.apple.com/documentation/devicemanagement/sending-mdm-commands-to-a-device).
