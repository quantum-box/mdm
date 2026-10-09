# Extended device operations

The iPad device-channel API and CLI include applications, kiosk mode, software
updates, lock/erase, ADE and Apps & Books. The Japanese console is at `/admin`.
All `/v1` routes require a Bearer token. Read tokens can inspect results but
cannot queue commands, change enrollment, or call Apple mutations.

## Device commands

Use `POST /v1/enrollments/{id}/commands` with an `idempotency_key` and a typed
`command`. `GET` on the same URL returns persisted command history with an
optional `after` cursor; `GET /v1/commands/{id}` returns one command and its
notification state. Typed command names include:

- `install_application`, `remove_application`, `installed_application_list`,
  `managed_application_list`.
- `available_os_updates`, `schedule_os_update`, `os_update_status`.
- `device_lock` and `device_configured`.

App Store install source is `{"AppStore":{"itunes_store_id":123456789,
"purchase_method":1}}`; enterprise source is
`{"Enterprise":{"manifest_url":"https://apps.example.com/manifest.plist"}}`.
Apps & Books device licenses must be assigned independently. Reissuing
InstallApplication requests the selected app's install/update; query installed
and managed app lists to observe its resulting version and status.

OS scheduling uses `updates` containing `product_key` or `product_version`,
`install_action` (`Default`, `DownloadOnly`, `InstallASAP`), and null
`max_user_deferrals`/`priority`. The service rejects macOS-only schedule fields,
lock PINs and erase obliteration behavior on this iPad-oriented boundary.

`GET /v1/enrollments/{id}/observations` returns authenticated query responses,
the corresponding command ID, dispatch timestamp, and receipt timestamp.
Supervision evidence comes from DeviceInformation `IsSupervised`, with a
24-hour freshness limit. OS query/scheduling and DeviceConfigured require
positive evidence; unknown or unsupervised devices are rejected. DeviceConfigured
also requires the device to have reported AwaitingConfiguration. Its ACK ends
that persisted state.

ACK indicates acceptance of a mutation, not completed app installation or OS
update. Read queries retry the same command UUID after timeout. Mutations become
`outcome_unknown` and block the generation queue until an operator investigates
and cancels unresolved local delivery. Notification acceptance is separate.

## Kiosk and erase

`POST /v1/enrollments/{id}/kiosk` accepts `bundle_id` and `idempotency_key`.
It creates a deterministic App Lock profile. Positive supervision and a fresh
InstalledApplicationList observation containing the target app are required.
The same checks apply to App Lock profiles submitted through generic
InstallProfile. Prerequisites are rechecked before dispatch; changed or expired
prerequisites fail locally without delivering the command.

`POST /v1/enrollments/{id}/kiosk/release` accepts `idempotency_key` and queues
RemoveProfile for the same enrollment-specific profile identifier.

Erase requires two requests. `POST /v1/enrollments/{id}/erase-intents` returns
`id`, secret `token`, `serial_number`, and epoch `expires_at` (five minutes).
`POST /v1/enrollments/{id}/erase` requires `intent_id`, `token`, `confirm_serial`,
and `idempotency_key`. Exact retry returns the same command. Wrong serial,
expired intent, reused intent with another key, revoked generation, or a
cross-generation request is rejected. Generic EraseDevice enqueue is rejected.
The CLI saves the prepared intent in a new mode-0600 file. Erase is irreversible
on the device; confirm only on an explicitly authorized disposable test device.

## Apple integrations

Set optional private credential files before starting the daemon:

```sh
export MDM_ADE_TOKEN_FILE=/secure/ade-token.p7m
export MDM_ADE_PROVIDER_CERT_FILE=/secure/ade-provider.pem
export MDM_ADE_PROVIDER_KEY_FILE=/secure/ade-provider-key.pem
export MDM_ADE_DEVICE_CA_FILE=/secure/apple-device-ca.pem
export MDM_VPP_TOKEN_FILE=/secure/apps-books-token
```

For a privately decrypted ADE JSON token, omit both provider-identity variables.
Token/key files must be mode 0600. Startup validates every configured file;
unconfigured integrations return 503 without contacting Apple.

`GET /v1/integrations/apple` exposes only configuration flags.
`GET /v1/ade/devices` reads locally synchronized devices. `POST /v1/ade/sync`
accepts `{}` for a full fetch or `{ "cursor": "…" }` to continue Apple sync.
Persist and continue Apple's returned cursor until `more_to_follow` is false.
The local device list is bounded at 1,000; large fleets should inspect the sync
pages directly. `POST /v1/ade/profiles` takes `profile` and `idempotency_key`.
The server pins the direct enrollment URL to its own `/ade/enroll` origin and
requires supervised, mandatory, nonremovable enrollment awaiting configuration.
Optional `anchor_certs` must describe the HTTPS trust chain, not the SCEP CA
unless that CA also issued the HTTPS certificate.

`POST /v1/ade/assign` and `/v1/ade/unassign` take `profile_uuid`, `devices`
(serial numbers), and `idempotency_key`. Synchronize after assignment to observe
Apple's device profile status before enrollment. `/ade/enroll` verifies the
CMS-signed MachineInfo against explicitly configured Apple Device CA anchors,
and accepts only serials assigned to a locally registered profile. Its initial
profile binds signed UDID and serial to one enrollment generation and one
SCEP challenge. Unused exact requests replay for 15 minutes; consumed, expired,
or revoked bootstrap state requires admin reset at
`POST /v1/ade/devices/{serial}/reset` before another initial enrollment.
Reset does not revoke an active identity; subsequent authenticated reenrollment
revokes and isolates the prior generation.

`POST /v1/apps/licenses` takes numeric `adam_id`, `serial_number`, `assign`,
and `idempotency_key`. Apple returns an asynchronous event, which is persisted.
`GET /v1/apps/licenses/{adam_id}?serial=…` reads the current Apple assignment and,
when available, the persisted event's current status. An accepted association
is not reported as a completed assignment or an installed application.

External mutations persist their request hash before network I/O. An uncertain
result remains `outcome_unknown`; retry with the same key is rejected rather
than sending a second mutation. Exact completed requests return the stored
result. Inspect Apple assignment/device state to reconcile uncertainty before
issuing a deliberate new operation.

Software fixtures verify these paths. Apple tenant and physical-device
acceptance remain in [the device checklist](device-test.md).
