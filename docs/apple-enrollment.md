# Automated Device Enrollment

`mdmd::apple` contains the Apple Automated Device Enrollment (ADE) adapter.
It uses the server-token protocol documented by Apple and does not implement a
second, private enrollment service.

## Credentials

Create a device-management server in Apple Business Manager or Apple School
Manager. Upload the public certificate for an RSA private key and download the
encrypted S/MIME server-token file. Keep the downloaded `.p7m`, the provider
certificate, and the provider private key outside the repository. The token and
private key files must be mode `0600` on Unix systems:

```sh
chmod 600 data/ade-server-token.p7m data/ade-provider-key.pem
```

The encrypted token is decrypted with CMS/RSA when
`AdeClient::from_encrypted_token` is constructed. The clear token contains
`consumer_key`, `consumer_secret`, `access_token`, and `access_secret`. The
adapter never includes those values in an error string or log message. A
manually decrypted JSON token can be loaded with `from_token_file`, also with
mode `0600`.

Every request first obtains a short-lived session from
`https://mdmenrollment.apple.com/session` using OAuth 1.0a HMAC-SHA1. Apple
requires the returned value in `X-ADM-Auth-Session`; a single `401` causes the
adapter to refresh the session and retry that request. The adapter sends the
Apple `User-Agent` and `X-Server-Protocol-Version` headers, disables redirects,
requires HTTPS for the production origin, and bounds response sizes and
timeouts.

## Synchronizing devices and profiles

The adapter maps directly to the Apple service endpoints:

| Operation | Request |
| --- | --- |
| Fetch devices | `POST /server/devices` |
| Continue synchronization | `POST /devices/sync` |
| Define profile | `POST /profile` |
| Read profile | `GET /profile?profile_uuid=...` |
| Assign profile | `POST /profile/devices` |
| Remove profile | `DELETE /profile/devices` |

Apple cursors expire after the period documented by Apple, so persist the last
successful cursor and restart with a full fetch after expiry. Assignment and
removal accept at most 1,000 serial numbers per request. The response is kept
as JSON so Apple can add status fields such as `THROTTLED` without the client
silently discarding them.

The profile passed to `define_profile` is an Apple `Profile` JSON object. URLs
inside it, including `url` and `configuration_web_url`, must be HTTPS. The
adapter sends the URL to Apple and never downloads it. Include the HTTPS server
certificate in `anchor_certs` when the device should pin a private deployment
CA. For the direct, token-based initial enrollment profile, `url` should point
to the device-facing ADE route, for example
`https://mdm.example.com/ade/enroll`. `configuration_web_url` belongs to the
separate interactive web-view enrollment flow.

## Initial device request

Apple's token-based ADE flow sends a CMS-signed `MachineInfo` plist to the
configured enrollment URL with content type
`application/pkcs7-signature`. The web-view flow sends the same information in
the `x-apple-aspen-deviceinfo` header on the initial HTTPS GET. The header is a
Base64-encoded CMS `SignedData` envelope. The plist contains the required
`SERIAL`, `UDID`, `PRODUCT`, `VERSION`, and `OS_VERSION` fields, along with
optional device capabilities on newer systems.

`parse_ade_machine_info` verifies the CMS signature and parses the bounded
plist; `parse_ade_machine_info_der` handles the raw body on the token-based
POST lane. Enrollment authorization must call `verify_ade_machine_info` (or
the DER variant) with the configured Apple Device CA trust anchors, then
compare the signed serial to an assigned device returned by ADE
synchronization. A self-reported serial in an unsigned query or header is never
enough to mint a profile. The server should only return the profile after the
CMS signer chain, serial assignment, and any operator authentication policy
pass. Return it with MIME type `application/x-apple-aspen-config`.

`build_ade_profile` creates the minimal direct enrollment Apple profile body
with the `url`, supervised/mandatory policy flags, and a DER `anchor_certs`
entry encoded as Base64. The caller must add the MDM payload fields required by
its policy before defining the profile. `configuration_web_url` is a separate
interactive web-view flow and is not used by this direct enrollment helper.

Apple documents that `AnchorCerts` pins the HTTPS host and that the returned
profile must originate from the configured host. Keep the profile route on the
same hostname and do not redirect it to a different origin.

## Operational boundaries

The adapter provides protocol calls and bounded parsers; it does not claim
that an Apple tenant is configured or that a physical device accepted a
profile. Use a dedicated test server and token for integration testing. Store
the Apple token and provider key in a secret manager or a private filesystem,
rotate them in Apple Business Manager when required, and restart the process
after replacement. Never print OAuth headers, CMS bytes, `MachineInfo`, serial
numbers, or decrypted token data in support logs.

Official references:

- [Authenticating for Automated Device Enrollment](https://developer.apple.com/documentation/devicemanagement/authenticating-for-automated-device-enrollment)
- [Examining Server Tokens](https://developer.apple.com/documentation/devicemanagement/examining-server-tokens)
- [Fetch Devices](https://developer.apple.com/documentation/devicemanagement/fetch-devices)
- [Assign a Profile](https://developer.apple.com/documentation/devicemanagement/assign-profile)
- [MachineInfo](https://developer.apple.com/documentation/devicemanagement/machineinfo)
- [Authenticating through web views](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
