# Cloudflare deployment

This document describes the Cloudflare Worker package included under
[`deploy/cloudflare`](../deploy/cloudflare). The package is implemented and
tested locally; this repository does not deploy it to a Cloudflare account or
claim Apple device acceptance. Cloudflare account credentials are deliberately
not required by the repository's build.

## Keep the Rust origin durable

Run one `mdmd` OCI origin with `/data` on persistent block storage. The
Cloudflare edge and Tunnel are stateless adapters in front of that process.
Do not mount a Rust `rusqlite` file from a Worker, Durable Object, `/tmp`, a
container layer, or a Cloudflare-only ephemeral filesystem. A provider-native
store can have its own consistency model; this origin must keep its SQLite
file on persistent block storage and remain a single SQLite writer.

The repository includes a Compose template and an example Tunnel ingress:

- [`compose.yaml`](../compose.yaml) has an origin and an optional sidecar in
  the same network namespace.
- [`config.yml.example`](../deploy/cloudflare/config.yml.example) connects the
  sidecar to a fixed HTTPS origin hostname, leaves TLS verification enabled,
  and uses `noTLSVerify: false`.

Copy the example to a deployment-only `config.yml`, replace the tunnel UUID,
private Tunnel/Access hostname, origin TLS name, and credentials path, then pin the
`cloudflare/cloudflared` image. The origin certificate must contain the fixed
`originServerName`; if it is privately issued, provide its CA through
`caPool`. Never use `noTLSVerify: true` as a shortcut.

## Device certificate boundary

Apple enrollment starts before the device owns an MDM client certificate. The
public endpoint therefore needs two policies:

| Path | Edge policy |
| --- | --- |
| `/scep` | HTTPS, anonymous at TLS, SCEP challenge and proof-of-possession enforced by `mdmd` |
| `/ade/enroll` | HTTPS, anonymous at TLS, signed ADE machine identity validated by `mdmd` |
| `/checkin` | Verified SCEP-issued device certificate, matching enrollment and UDID |
| `/mdm` | Verified SCEP-issued device certificate, matching enrollment and UDID |
| `/v1/*` | Operator bearer token plus the gateway/origin authorization boundary |

Cloudflare BYOCA mTLS and Access mTLS can enforce a client certificate at the
edge, but availability and policy features depend on the Cloudflare plan.
BYOCA is documented as an Enterprise feature. A host-wide mandatory mTLS
policy will block SCEP bootstrap, so use path-specific rules or a gateway that
allows `/scep` anonymously and requires a certificate for device paths.

References: [Cloudflare BYOCA](https://developers.cloudflare.com/ssl/client-certificates/byo-ca/),
[client certificates](https://developers.cloudflare.com/ssl/client-certificates/),
[Access mTLS](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/mutual-tls-authentication/),
and [path-specific Access applications](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/).

The standard HTTP Tunnel does not preserve the Apple device's original TLS
client certificate to the origin; Cloudflare terminates the public connection
and makes a separate origin connection. A direct native-TLS deployment or a
true L4 TLS passthrough service is needed when the origin itself must see the
device certificate. Cloudflare Spectrum's passthrough availability is plan
dependent: [Spectrum configuration](https://developers.cloudflare.com/spectrum/reference/configuration-options/)
and [protocols by plan](https://developers.cloudflare.com/spectrum/protocols-per-plan/).

## Worker gateway

The Worker/gateway adapter is a separate deployment artifact. It should expose
the Apple public host and route to the fixed origin URL over HTTPS. Keep these
controls separate:

1. Cloudflare Access service authentication protects the Worker-to-origin
   connection and prevents a caller from bypassing the Worker through the
   origin hostname.
2. The gateway HMAC key authenticates the signed request envelope consumed by
   the Rust gateway adapter. It is not the Access client secret and must not be
   reused for it.
3. The Worker verifies Cloudflare client-certificate fields, strips any
   caller-supplied certificate forwarding headers, and writes the canonical
   signed peer information. A forwarded header alone is never an identity.

Cloudflare's RFC9440 fields expose the certificate and verification flags to a
Worker. Check `certVerified`, `certRevoked`, and the size flags before signing;
do not use the legacy first-request certificate forwarding behavior. See
[certificate forwarding](https://developers.cloudflare.com/ssl/client-certificates/forward-a-client-certificate/)
and the [Worker RFC9440 fields](https://developers.cloudflare.com/changelog/post/2026-03-27-rfc9440-mtls-fields/).

Use a separate public and origin name:

```text
MDM_PUBLIC_URL=https://mdm.example.com
Worker origin=https://mdm-origin.example.com
Worker -> Access/Tunnel hostname=mdm-origin.example.com
Tunnel -> Rust originServerName=mdm-origin.internal.example
Gateway HMAC key=Worker secret == MDM_GATEWAY_KEY_FILE on the origin
```

The public value is embedded into enrollment profiles. The Worker origin
hostname must resolve from the Worker/Tunnel path and be protected by
Cloudflare Access or an equivalent network policy; block direct public
TCP/HTTP access to the Rust listener. The Tunnel's `originServerName` must
match the certificate presented by the Rust origin. The SCEP request must be
allowed through the Worker without a device certificate, while the Worker
must still enforce the enrollment challenge and request bounds at the origin.

If the selected Cloudflare/AWS edge cannot express path-specific mTLS, set
`MDM_BOOTSTRAP_URL` to an anonymous SCEP/ADE hostname and keep
`MDM_PUBLIC_URL` on the device hostname. The enrollment profile builder then
uses the bootstrap URL only for `/scep` and ADE enrollment; `/checkin` and
`/mdm` remain on `MDM_PUBLIC_URL` and require the issued device certificate.
Validate the generated profile before sending it to a device.

The current protocol limits SCEP GET `PKIOperation` messages to a 16 KiB
encoded query value. Cloudflare and Worker URL limits include the complete URL,
so use SCEP POST for large requests and keep edge request-line limits below the
provider maximum. The Worker must not cache `/scep`, `/checkin`, `/mdm`, or
`/v1/*`; preserve PUT and the Apple XML/plist content types and the origin's
`Cache-Control: no-store` response.

Run the included Worker package checks before deployment:

```sh
cd deploy/cloudflare
npm ci
npm run check
npm test
npx wrangler secret put MDM_GATEWAY_KEY
npx wrangler secret put CF_ACCESS_CLIENT_ID
npx wrangler secret put CF_ACCESS_CLIENT_SECRET
npx wrangler deploy --config wrangler.jsonc
```

The two Access secret commands are required together or omitted together.
Replace `MDM_ORIGIN_URL` and the custom route in `wrangler.jsonc` before
deploying. Store the origin URL, Access service credentials, and gateway HMAC
key as Worker secrets/variables. Never commit Wrangler secrets or tunnel
credentials. The Worker source and the Rust origin are tested independently;
the deployment still requires a real Cloudflare zone and an origin
certificate.

## Tunnel operation

Run cloudflared with a pinned version and `--no-autoupdate`; the tunnel token or
credentials JSON belongs in a secret mount. Keep its metrics listener private
and scrape it from the platform. Configure outbound egress for cloudflared,
DNS, and the origin's APNs HTTPS connection; the Tunnel does not proxy
`api.push.apple.com` for the Rust worker.

Test the route in this order:

1. The gateway `/health` response reports edge liveness; separately probe the
   private origin `/health` over its verified HTTPS path or through a signed
   gateway request.
2. SCEP GetCACert and a synthetic POST succeed without a device certificate.
3. An unissued or revoked device certificate is rejected by the gateway.
4. A valid issued certificate reaches `/checkin` and `/mdm` with the expected
   signed peer identity.
5. A direct request to the origin hostname is blocked by network policy or
   Access service authentication.
6. Operator bearer tokens remain required at `/v1/*`.

The [deployment guide](deployment.md) covers shutdown and encrypted SQLite
backup. A Tunnel restart must not change the origin database or enrollment CA.
