# Apps & Books device distribution

`mdmd::apple::VppClient` uses Apple's location-based Apps & Books content token
with the v2 Device Management service. It handles device-based licenses only;
user assignment and legacy license endpoints are outside this adapter.

## Token handling

Download a location token from Apple Business Manager or Apple School Manager,
store it as a private file, and set mode `0600`:

```sh
chmod 600 data/apps-books-token
```

`VppClient::from_token_file` accepts Apple's downloaded Base64-encoded JSON
location token (with `token`, `expDate`, and `orgName`), as well as a JSON
wrapper containing `sToken`, `s_token`, `token`, or `content_token`. A plain
opaque token is also accepted for secret-manager integrations. The complete
location token is sent only as an `Authorization: Bearer` header to Apple's
fixed HTTPS origin
`https://vpp.itunes.apple.com/mdm/v2`. It is never returned in an error or
included in a request body.

## Device license calls

The adapter maps to the current Apps & Books v2 endpoints:

| Operation | Request |
| --- | --- |
| Service metadata | `GET /service/config` |
| Search assets | `GET /assets` |
| Associate licenses | `POST /assets/associate` |
| Disassociate licenses | `POST /assets/disassociate` |
| Device license status | `GET /assignments?adamId=...&serialNumber=...` |
| Poll operation | `GET /status?eventId=...` |

Association and disassociation bodies contain `assets` (`adamId` and optional
`pricingParam`) and `serialNumbers`. The Apple response is asynchronous and
returns an `eventId`; persist that ID and poll `status` until Apple reports the
terminal state. A successful HTTP response only means that Apple accepted the
operation for processing.

`assignment` (also exposed as `license_status`) reads the assignment for one
Adam ID and one device serial number through Apple's `/assignments` endpoint.
This is the device license view needed by an operator after an asynchronous
associate or disassociate operation; it does not replace polling the returned
`eventId`.

Before assigning, query `/assets` with `deviceAssignable=true` and select an
asset Apple marks as device-assignable. Books, subscriptions, and assets that
require a user assignment must follow Apple's separate user-assignment flow.
The adapter does not claim that a license reached a device until the status
operation and the MDM device result are both recorded.

## App installation URL boundary

An app installation command may contain an HTTPS manifest URL hosted by the
operator. `validate_manifest_url` rejects `file:`, plain HTTP, credentials,
and fragments. `VppClient` never fetches this URL, follows a redirect, or acts
as a blind proxy. The device downloads the manifest directly over HTTPS, so
serve it from a host and certificate reachable and trusted by the device.

Keep the manifest and any package authorization on the operator's HTTPS
origin. Do not place an Apps & Books token, API credential, or device serial in
the URL. Keep token, license operation IDs, and Apple response payloads out of
normal logs; redact them in diagnostics.

## Acceptance and recovery

The repository includes a loopback fixture that checks endpoint paths, bearer
authentication, device-only request shape, assignment lookup, asynchronous
status handling, and secret masking. It does not replace acceptance against an
Apple tenant. Before production use, verify a real device-assignable app in a
dedicated Apple
location, observe an `eventId` through completion, and confirm the MDM command
and device response. If an operation is interrupted, resume by polling the
persisted event ID instead of submitting a blind duplicate.

Official references:

- [Managing assets](https://developer.apple.com/documentation/devicemanagement/managing-assets)
- [Setting up and assigning content](https://developer.apple.com/documentation/devicemanagement/setting-up-and-assigning-content)
- [Service configuration](https://developer.apple.com/documentation/devicemanagement/service-config)
- [Get assignments](https://developer.apple.com/documentation/devicemanagement/get-assignments-9wv1e)
