# Lambda and event-driven gateways

The repository includes an AWS Lambda gateway at
[`deploy/lambda/handler.mjs`](../deploy/lambda/handler.mjs) and the shared
portable envelope in [`deploy/gateway/index.mjs`](../deploy/gateway/index.mjs).
The gateway is implemented and tested, but it does not run the stateful
`mdmd` engine. The durable Rust origin, SQLite state, APNs outbox, and
long-lived device listener remain outside Lambda.

## Gateway boundary

The included adapter handles an API Gateway HTTP API v2 event behind a custom
domain with mutual TLS. It terminates the public TLS connection and passes
verified client certificate material to a Lambda gateway. The gateway must
translate that material into the same authenticated peer contract as native
Rust TLS:
certificate bytes, leaf fingerprint, expiry, and verification result. It then
forwards a signed request to the fixed HTTPS Rust origin using origin service
authentication and the gateway HMAC key.

AWS references: [API Gateway HTTP API mutual TLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)
and [API Gateway DomainName mTLS properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-domainname-mutualtlsauthentication.html).

An ALB mTLS event adapter is outside the included package. If an ALB is used,
it must provide an equivalent verified certificate-to-peer translation before
the shared gateway envelope is sent to the Rust origin.

The gateway must preserve the bootstrap split. SCEP requests are anonymous at
TLS and rely on the one-time enrollment challenge; `/checkin` and `/mdm` need a
verified device certificate; `/v1/*` needs an operator bearer token. Do not
accept a client certificate header from an untrusted event body. API Gateway
truststore configuration must validate the chain before the adapter signs a
request.

When an edge cannot express path-specific mTLS, configure an anonymous
`MDM_BOOTSTRAP_URL` for SCEP/ADE and keep `MDM_PUBLIC_URL` on the device host.
Only `/scep` and ADE enrollment use the bootstrap URL; `/checkin` and `/mdm`
stay on `MDM_PUBLIC_URL`. The bootstrap URL is still HTTPS and is not a bypass
of the SCEP challenge.

Run the shared gateway checks from the Cloudflare package directory; they also
syntax-check the Lambda handler:

```sh
cd deploy/cloudflare
npm ci
npm run check
npm test
```

The included SAM template's exact validate/build/deploy commands and parameter
names are maintained in [`deploy/lambda/README.md`](../deploy/lambda/README.md).
CDK, Terraform, or another AWS workflow must produce the same API Gateway HTTP
API v2 and truststore settings. Set `MDM_GATEWAY_KEY` and `MDM_ORIGIN_URL`
through the template's secret and parameter inputs, and configure the API
Gateway custom domain truststore/mTLS before exposing the function.

## Why Lambda is not the engine runtime

Lambda `/tmp` is temporary and belongs to one execution environment. It is not
a shared durable SQLite volume. The process also cannot host the current
long-lived TCP listener, APNs HTTP/2 worker, SQLite WAL writer, and graceful
shutdown contract as a normal Lambda handler. AWS documents `/tmp` as
ephemeral storage and recommends treating execution environments as reusable
but not durable: [ephemeral storage](https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html)
and [best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html).

Do not place `mdm.sqlite` in `/tmp`, EFS, S3, or an invocation-local layer and
assume that SQLite command ordering or WAL locking remains the same. For this
engine, use a persistent block volume with one origin process. A Lambda-native
engine would need all of the following before it could claim support:

- a durable transactional `StateStore` with idempotency and generation locks;
- a durable notification/outbox queue and an external scheduler for APNs;
- a bounded event adapter for PUT/XML/plist and SCEP binary bodies;
- certificate truststore validation and authenticated peer translation;
- retry, lease, timeout, and `outcome_unknown` handling across invocations;
- a durable backup/restore and key-rotation process;
- an integration test covering concurrent delivery and a replayed event.

Those stateful components are outside the OCI image and the Lambda gateway.
The gateway itself is implemented; an all-Lambda engine still requires
explicit storage, worker, and transport implementations rather than
provider-specific conditionals in the protocol model. The fully serverless
StateStore/outbox design is tracked separately in
[PLT-5781](https://linear.app/quantum-box/issue/PLT-5781).

## Secret and origin controls

Use Lambda/Secrets Manager for the API Gateway truststore reference, Access or
origin service credentials, and gateway HMAC key. Do not put admin tokens in
Lambda event fields or URL query parameters. The Worker/Lambda HMAC key is
distinct from the origin TLS key and from the Cloudflare/AWS service-auth
credential.

The origin should accept requests only from the private gateway path. A public
origin with `--trust-proxy` is unsafe because a caller could forge certificate
headers. Keep `MDM_PUBLIC_URL` set to the Apple-facing gateway URL and use a
separate fixed origin hostname for gateway-to-origin TLS verification.

No AWS account deployment is performed by this repository. The required
origin Docker image and persistent-volume operation are documented in
[`deployment.md`](deployment.md); the gateway package still needs a real
API Gateway truststore, domain, credentials, and device acceptance review.
