# AWS Lambda gateway

<!-- SPDX-License-Identifier: MIT -->

Use the Node.js 22 Lambda runtime. `handler.mjs` is an AWS API Gateway HTTP
API payload version 2 adapter for the same portable gateway module used by the
Cloudflare Worker. `template.yaml` is a deployable AWS SAM stack: it creates
two HTTP APIs backed by this gateway, one device API and one bootstrap API,
with optional custom domains. The function contains no SQLite or APNs
scheduler; keep those in the persistent Rust origin.

From the repository root, create a Secrets Manager secret whose raw
`SecretString` is the same 32-128 character gateway key configured at the
Rust origin, then build and deploy the stack:

```sh
sam validate --template-file deploy/lambda/template.yaml
sam build --template-file deploy/lambda/template.yaml
sam deploy --guided --template-file .aws-sam/build/template.yaml \
  --parameter-overrides \
  MdmOriginUrl=https://mdm-origin.internal.example \
  GatewaySecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:mdm-gateway-key
```

The template reads the key, and optional API Gateway-to-origin Access
credentials, through CloudFormation Secrets Manager dynamic references. No
key is stored in the repository. `MdmOriginUrl` is fixed configuration and
must be the HTTPS origin root; redirects, paths, and query strings are
rejected by the gateway. SAM's `makefile` build copies only `handler.mjs` and
the shared gateway module into the artifact, so installed Wrangler packages,
tunnel credentials, tests, and the Rust workspace are not uploaded.
The template rules reject partial Access credentials or partial custom-domain
configurations. Keep `sam build` on the native builder for this layout; the
shared gateway is a sibling of the Lambda `CodeUri`, so this repository does
not promise that `sam build --use-container` mounts that sibling into the
provider build container.

Set `DeviceDomainName`, `DeviceCertificateArn`, and `DeviceTruststoreUri` to
enable the device custom domain with API Gateway mTLS. Set
`BootstrapDomainName` and `BootstrapCertificateArn` for a separate anonymous
bootstrap hostname. The split is required when mTLS is host-wide: SCEP and
ADE bootstrap need anonymous TLS while `/checkin` and `/mdm` require a
verified client certificate. After both DNS records are ready, set
`DisableExecuteApiEndpoint=true` to prevent direct `execute-api` access. The
template does not create DNS records or the ACM/S3 truststore; provision and
verify those resources separately. The stack outputs
`DeviceRegionalDomainName`/`DeviceRegionalHostedZoneId` and
`BootstrapRegionalDomainName`/`BootstrapRegionalHostedZoneId` for the Route
53 alias records.

API Gateway mutual TLS validation is the certificate boundary. The adapter
uses only `requestContext.authentication.clientCert.clientCertPem` and ignores
certificate-looking request headers. Binary Apple plist bodies and responses
are always represented as base64 in the Lambda response. `rawPath` and
`rawQueryString` are retained in the signed envelope.

The API Gateway HTTP API mTLS setup described here follows AWS's [HTTP API
mTLS guide](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)
and the [CloudFormation DomainName mTLS
properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-domainname-mutualtlsauthentication.html).

For API Gateway, configure a custom domain with an API Gateway truststore and
mTLS for the device hostname. Bootstrap routes (`/scep`, `/ade/enroll`, and
operator bootstrap) must remain reachable anonymously, so use the separate
bootstrap API/custom domain in the template when the provider applies mTLS to
an entire hostname. Both APIs invoke the same handler and fixed origin. The
Rust origin still revalidates the signed leaf against its enrollment CA.

The gateway's `/health` response is an edge liveness check. It does not probe
the Rust origin. Keep the origin listener private and expose origin health
only through an authenticated gateway or a separate trusted operations path;
a reverse proxy may connect from loopback, so loopback peer detection alone
must not make an origin health endpoint public.
