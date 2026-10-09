# Declarative device management

Enable DDM explicitly for an active enrollment with `mdmd ddm enable`.
The enrollment profile does not need a DDM `ServerCapabilities` entry.
This foundation targets profile-based iPad device enrollment on iPadOS 16+.
A stored OS version is a compatibility guard, not hardware attestation; select
an actual iPad and record its OS in acceptance evidence. Real DDM acceptance
has not been performed.

Supported declaration types are `com.apple.activation.simple`,
`com.apple.configuration.app.managed`,
`com.apple.configuration.management.status-subscriptions`, and
`com.apple.management.server-capabilities`. AppManaged is limited to one
AppStoreID, BundleID, or HTTPS ManifestURL source and the InstallBehavior
Install/License subset. Assets, legacy-profile takeover, app configuration,
software updates, user channels, and custom policy languages are outside this
foundation. Unsupported declaration types are rejected.

## Configure status subscriptions

Save `subscriptions.json`:

```json
{
  "Type": "com.apple.configuration.management.status-subscriptions",
  "Identifier": "status-subscriptions",
  "ServerToken": "subscriptions-v1",
  "Payload": {
    "StatusItems": [{"Name": "device.operating-system.version"}]
  }
}
```

Save `activation.json`:

```json
{
  "Type": "com.apple.activation.simple",
  "Identifier": "status-activation",
  "ServerToken": "activation-v1",
  "Payload": {"StandardConfigurations": ["status-subscriptions"]}
}
```

1. Enable: `mdmd ddm enable ENROLLMENT_ID --idempotency-key ddm-first-enable`.
2. Publish: `mdmd ddm put --file subscriptions.json` and `mdmd ddm put --file activation.json`.
3. Assign: `mdmd ddm targets status-subscriptions --enrollment ENROLLMENT_ID` and `mdmd ddm targets status-activation --enrollment ENROLLMENT_ID`.
4. Inspect reports: `mdmd ddm status ENROLLMENT_ID`.
5. Inspect declarations and assignments: `mdmd ddm list`.

Target replacement supplies the complete set. An empty set removes all
targets. Targets are immutable enrollment-generation IDs. Reenrollment needs
explicit enablement and assignments for the new generation. An old
certificate cannot read declarations or submit reports.

## Revisions, deletion, and delivery

Keep `Identifier` stable and change the opaque `ServerToken` whenever content
changes. Exact resubmission is idempotent. Reusing a current token with a
different body, reusing a historical token, or changing an identifier's
category returns 409. Recreation after deletion needs a fresh token.
Identifiers must fit one endpoint path segment.

`mdmd ddm delete status-subscriptions --server-token subscriptions-v1`
checks the current token; stale deletion is rejected. Removed targets see a
new manifest token. A missing, unassigned, wrong-category, or deleted
declaration returns 404. Delete the activation first when removing its
configuration. Missing references may be reported by the device; the server
does not invent or repair policy.

Every declaration/target edit, required synchronization command, and APNs
outbox entry commit in one transaction. A pending synchronization command
without Data can cover several edits because the device fetches current
tokens. In-flight commands are never rewritten. APNs acceptance and DDM
command ACK do not establish declaration application. A response timeout is
`outcome_unknown`; investigate reports before explicitly cancelling it.

## Device protocol and status semantics

Authenticated `PUT /checkin` accepts Apple `DeclarativeManagement` plist
requests for `tokens`, `declaration-items`, `declaration/{category}/{identifier}`,
and `status`. Fetch replies are JSON. Status Data is plist binary data
containing a JSON `StatusReport`; receipt returns an empty HTTP 200.
The identity, UDID, active state, and enabled enrollment generation must agree.

Reports retain `StatusItems`, `Errors`, and `FullReport`. Identical reports are
deduplicated per generation, retaining their first receipt time. Distinct
reports, including old revision reports, remain visible. `received_at` and
cursors describe server receipt, not device execution order. Reports have no
universal monotonic sequence; this API exposes observations instead of
claiming current state by overwriting it with a late report. `FullReport` is
preserved for consumers implementing a reconciliation policy.

The selected declarations claim no traditional profile settings.
InstallProfile/RemoveProfile retain their command model. The legacy profile
bridge is rejected; profile ownership cannot transfer implicitly.

## Management API

Endpoints use the existing administrator/read-only bearer roles.

| Method and path | Request / result |
| --- | --- |
| `POST /v1/enrollments/{id}/ddm/enable` | `{ "idempotency_key": "..." }`; command ID |
| `GET /v1/enrollments/{id}/ddm/status?after=0` | Reports, receipt ordering, cursor |
| `GET /v1/declarations?after=IDENTIFIER` | Declarations, targets, deleted flag, cursor |
| `POST /v1/declarations` | Selected Apple declaration JSON |
| `PUT /v1/declarations/{id}/targets` | `{ "enrollment_ids": ["..."] }`; full replacement |
| `DELETE /v1/declarations/{id}?server_token=TOKEN` | Delete matching current revision |

List APIs return up to 100 items. Target replacement accepts up to 100 IDs.
Each enrollment has at most 256 assigned declarations and 256 outstanding
commands. Queue-limit failures roll back declaration/target changes.
Declaration JSON is bounded to 256 KiB. Audit entries record identifiers and
action names rather than declaration bodies or reports.

See the pinned [protocol sources](../crates/mdm-protocol/docs/protocol-sources.md)
and the [real-device checklist](device-test.md).
