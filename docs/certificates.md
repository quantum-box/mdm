# MDM certificates

The service uses a private SCEP CA for enrollment and an Apple MDM push
certificate for APNs. Keep the SCEP CA key and the APNs identity key outside the
repository and outside request logs.

## Create the SCEP CA

Run the service's initialization command once with paths on a protected local
volume. It creates a 3072-bit RSA CA and refuses to overwrite either path:

```text
mdmd init-ca --cert /etc/mdm/ca.pem --key /etc/mdm/ca-key.pem
chmod 600 /etc/mdm/ca-key.pem
```

The CA certificate is published by the SCEP `GetCACert` endpoint in DER form.
The `GetCACaps` endpoint advertises `POSTPKIOperation`, `SHA-256`, and `AES`
support. The same certificate is the combined SCEP CA/RA identity: its key
usage includes `keyCertSign`, `crlSign`, `digitalSignature`, and
`keyEncipherment`. The private key decrypts incoming SCEP EnvelopedData and
signs both CertRep responses and issued device certificates.

## SCEP enrollment

An enrollment request must contain:

1. An outer PKCS#7 `SignedData` with a valid signature and a self-signed signer certificate.
2. An inner PKCS#7 `EnvelopedData`, encrypted to the SCEP CA, containing a PKCS#10 CSR with a valid signature and a `challengePassword`.
3. A matching RSA 2048–4096 bit signer/CSR key, an exact enrollment common name, `messageType=19`, a transaction ID, and a sender nonce.

The service verifies the outer signature before decrypting the inner
EnvelopedData and limits the total request to 1 MiB. The signer certificate
public key must match the CSR key. The CSR common name must exactly match the
enrollment ID.
The signed CertRep response is encrypted to the request signer certificate.
Issued device certificates are valid for 365 days and are never issued past
the CA's expiry.

The enrollment record is created before SCEP issuance. During issuance, consume
the challenge and persist the issued certificate fingerprint, exact request
hash, and CertRep response in one database transaction. A retransmitted request
therefore receives the same response. Do not store or log the challenge in
plaintext.

## Built-in HTTPS

The standalone binary can terminate HTTPS itself. Pass the server certificate
chain and its matching private key to `mdmd serve`; the key must be mode `0600`.
The listener requires TLS 1.2 or newer, requests an optional client
certificate, and validates device certificates against the SCEP CA before
binding `/checkin` and `/mdm` to the issued fingerprint. Bootstrap SCEP and
operator routes remain usable without a client certificate.

```text
mdmd serve ... \
  --tls-cert /etc/mdm/tls/server-chain.pem \
  --tls-key /etc/mdm/tls/server-key.pem
```

Use a certificate whose public name matches the enrollment profile's HTTPS
host and whose chain is trusted by Apple devices. A reverse proxy is optional;
when used, keep the service on loopback and enable `--trust-proxy` with the
configuration in [`nginx.conf`](./nginx.conf).

## Reverse proxy client certificates

Terminate TLS at the reverse proxy with client verification enabled. Pass the
URL-escaped leaf certificate in `X-MDM-Client-Cert`; the application validates
the leaf chain against the SCEP CA, checks its validity period and TLS client
authentication purpose, and records the SHA-256 fingerprint. The application
must reject a missing, malformed, expired, or untrusted header value.

See [`nginx.conf`](./nginx.conf) for the smallest working proxy fragment.

## APNs MDM identity

`ApnsClient` accepts a PEM bundle containing the MDM leaf certificate and its
private key; keep that bundle at mode `0600`. The leaf certificate must still
be valid and its subject `UID` must exactly match the configured MDM topic.
APNs requests use
`https://api.push.apple.com`, HTTP/2, `apns-push-type: mdm`, priority `10`, and
the payload `{ "mdm": "<push magic>" }` only. Device tokens, push magic values,
and private key material must never be written to logs.

Rotate the APNs certificate before expiry and deploy the new bundle atomically.
The running process loads the identity at startup, so replace the bundle and
restart the worker after checking that the new leaf `UID` is unchanged. Keep
the previous bundle available for rollback until an APNs acceptance test has
passed. When an enrollment or APNs certificate is revoked, stop sending
immediately and remove the associated key from the service's key store.

## Rotation and recovery

The SCEP CA is the trust anchor for every issued device identity. Keep its
certificate and private key together with every database backup and validate
that they still match before restoring the database. Replacing the CA changes
the device trust chain; there is no automatic SCEP renewal path, so a CA
replacement requires a planned migration, new enrollment profiles, and device
re-enrollment. Do not overwrite the existing CA files with a newly generated
pair.

The HTTPS server certificate and key can be rotated independently when the new
chain remains trusted by the device and its hostname matches the enrollment
profile URL. Stage the new chain and mode-`0600` key, stop `mdmd`, replace both
files atomically, and start it again. Keep the previous pair for rollback
until a device-side TLS check succeeds.

The SQLite backup contains enrollment state, SCEP replay responses, device
fingerprints, and notification state, but no CA or APNs private keys. Use the
filesystem-only restore command from [the operations runbook](./operations.md)
to validate a backup and restore it to a new destination. A restore must use
the original CA key and an APNs identity with the same topic; otherwise
existing device identities or push notifications cannot continue safely.
