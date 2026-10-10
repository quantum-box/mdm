# Cloudflare gateway

<!-- SPDX-License-Identifier: MIT -->

This Worker is an edge gateway for the portable `mdmd` Rust origin. It does
not contain SQLite, the APNs worker, or command state. Keep the origin on a
persistent filesystem (for example, the OCI deployment described in
[`docs/deployment.md`](../../docs/deployment.md)) and point `MDM_ORIGIN_URL`
at its fixed HTTPS origin.

Install and validate the Worker from this directory, then set the required
secret with Wrangler:

```sh
npm ci
npm run check
npm test
npx wrangler secret put MDM_GATEWAY_KEY
npx wrangler secret put CF_ACCESS_CLIENT_ID
npx wrangler secret put CF_ACCESS_CLIENT_SECRET
npx wrangler deploy --config wrangler.jsonc
```

The value must be the same 32 to 128 byte ASCII key configured for the Rust
origin gateway. Cloudflare Access service credentials are Worker secrets named
`CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET`; configure both or neither.

`workers_dev` is disabled intentionally. Replace the placeholder custom route
in `wrangler.jsonc` with a domain attached to the zone and configure API Shield
mTLS for that hostname. Cloudflare's verified client certificate metadata is
used only for `/checkin` and `/mdm`; the origin still validates the signed leaf
against its enrollment CA. Anonymous SCEP, ADE enrollment, and management
requests reach the Rust origin, where the existing bearer or protocol
validation applies.

`GET /health` is a local, no-store gateway liveness response; it does not
prove that the Rust origin or APNs credentials are ready. The Worker forwards
all other requests exactly once with a 30 second timeout, signs the raw path
and query, strips caller supplied gateway/certificate headers, rejects origin
redirects, bounds request bodies to 2 MiB, and marks responses `no-store`.
Retries and command delivery recovery remain in the durable Rust outbox.

Keep the Rust origin's `/health` listener private or put it behind an
authenticated operations path. A local Tunnel or reverse proxy can make an
external caller appear loopback to the origin, so loopback peer detection
must not be treated as public health authorization.

Cloudflare-only deployment is deliberately unsupported for this service:
Worker, Containers, D1, Durable Objects, and R2 do not provide a drop-in
replacement for the origin's local SQLite WAL plus resident APNs worker. Use
this Worker with a persistent Rust origin over HTTPS. A Tunnel can publish the
origin privately, but Apple devices need an HTTPS endpoint; configure an HTTPS
Tunnel route or another TLS-capable origin path rather than a client-only TCP
route.
