use anyhow::{Result, anyhow};
use mdm_core::AppleDeclaration;
use mdm_protocol::{
    CheckIn, CommandPayload, DeviceResponse, parse_checkin, parse_response, parse_tokens_response,
};
use mdmd::{
    recovery::{restore_database, validate_backup},
    storage::{IssuedCertificate, RESPONSE_TIMEOUT_SECONDS, Store, digest},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::io::Cursor;
use tempfile::tempdir;

const BASE_TIME: i64 = 1_800_000_000;
const OLD_UDID: &str = "00000000-0000-0000-0000-000000000001";
const NEW_UDID: &str = "00000000-0000-0000-0000-000000000002";
const TOPIC: &str = "com.apple.mgmt.test";

fn authenticate_xml(udid: &str, os_version: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string>
<key>UDID</key><string>{udid}</string>
<key>Topic</key><string>{TOPIC}</string>
<key>SerialNumber</key><string>SYNTHETIC-DDM</string>
<key>OSVersion</key><string>{os_version}</string>
</dict></plist>"#
    )
    .into_bytes()
}

fn token_update_xml(udid: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MessageType</key><string>TokenUpdate</string>
<key>UDID</key><string>{udid}</string>
<key>Topic</key><string>{TOPIC}</string>
<key>Token</key><data>AQIDBA==</data>
<key>PushMagic</key><string>push-magic-{udid}</string>
<key>AwaitingConfiguration</key><false/>
</dict></plist>"#
    )
    .into_bytes()
}

fn active_enrollment(
    store: &Store,
    fingerprint: &str,
    udid: &str,
    os_version: &str,
    time: i64,
) -> Result<String> {
    let challenge = format!("challenge-{fingerprint}");
    let enrollment_id = store.create_enrollment(&challenge, time)?;
    store.issue_identity(
        &challenge,
        &format!("request-{fingerprint}"),
        time + 1,
        |_id| {
            Ok(IssuedCertificate {
                fingerprint: fingerprint.to_owned(),
                expires_at: "2035-01-01T00:00:00Z".to_owned(),
                response: format!("cert-reply-{fingerprint}").into_bytes(),
            })
        },
    )?;
    let authenticate = parse_checkin(&authenticate_xml(udid, os_version))?;
    assert!(matches!(authenticate, CheckIn::Authenticate { .. }));
    store.checkin(fingerprint, &authenticate, time + 2)?;
    let token_update = parse_checkin(&token_update_xml(udid))?;
    assert!(matches!(token_update, CheckIn::TokenUpdate { .. }));
    store.checkin(fingerprint, &token_update, time + 3)?;
    Ok(enrollment_id)
}

fn activation(identifier: &str, token: &str, name: &str) -> AppleDeclaration {
    AppleDeclaration::new(
        "com.apple.activation.simple",
        identifier,
        token,
        json!({"StandardConfigurations": [name]}),
    )
    .expect("test declaration is valid")
}

fn enable(store: &Store, enrollment_id: &str, time: i64) -> Result<String> {
    store.enable_ddm(enrollment_id, &format!("ddm-key-{enrollment_id}"), time)
}

fn request(
    store: &Store,
    fingerprint: &str,
    udid: &str,
    endpoint: &str,
    data: Option<&Value>,
    time: i64,
) -> Result<Option<Value>> {
    store.ddm_request(fingerprint, udid, endpoint, data, time)
}

fn declaration_items(response: &Value) -> &Value {
    response
        .get("Declarations")
        .expect("declaration-items response has Declarations")
}

fn tokens(store: &Store, fingerprint: &str, udid: &str, time: i64) -> Result<Value> {
    let response = request(store, fingerprint, udid, "tokens", None, time)?
        .ok_or_else(|| anyhow!("tokens must return a body"))?;
    let parsed = parse_tokens_response(&serde_json::to_vec(&response)?)?;
    assert!(!parsed.sync_tokens.declarations_token.is_empty());
    Ok(response)
}

fn response_xml(udid: &str, command_uuid: &str, status: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>{status}</string>
<key>CommandUUID</key><string>{command_uuid}</string>
</dict></plist>"#
    )
    .into_bytes()
}

fn acknowledged_response(udid: &str, command_uuid: &str) -> Result<DeviceResponse> {
    Ok(parse_response(&response_xml(
        udid,
        command_uuid,
        "Acknowledged",
    ))?)
}

fn idle_response(udid: &str) -> Result<DeviceResponse> {
    Ok(parse_response(
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>Idle</string>
</dict></plist>"#
        )
        .as_bytes(),
    )?)
}

fn install_profile() -> CommandPayload {
    CommandPayload::InstallProfile {
        payload: br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PayloadContent</key><array/>
<key>PayloadIdentifier</key><string>com.example.ddm.profile</string>
<key>PayloadOrganization</key><string>Example Organization</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>00000000-0000-0000-0000-000000000003</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
            .to_vec(),
    }
}

fn remove_profile() -> CommandPayload {
    CommandPayload::RemoveProfile {
        identifier: "com.example.ddm.profile".to_owned(),
    }
}

fn device_information() -> CommandPayload {
    CommandPayload::DeviceInformation {
        queries: vec!["UDID".to_owned()],
    }
}

fn app_managed(identifier: &str, token: &str, install: &str) -> AppleDeclaration {
    AppleDeclaration::new(
        "com.apple.configuration.app.managed",
        identifier,
        token,
        json!({
            "AppStoreID": "123456789",
            "InstallBehavior": {
                "Install": install,
                "License": {"Assignment": "Device"}
            }
        }),
    )
    .expect("test AppManaged declaration is valid")
}

fn supervision_response_xml(udid: &str, command_uuid: &str, supervised: bool) -> Vec<u8> {
    let value = if supervised { "true" } else { "false" };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>Acknowledged</string>
<key>CommandUUID</key><string>{command_uuid}</string>
<key>QueryResponses</key><dict><key>IsSupervised</key><{value}/></dict>
</dict></plist>"#
    )
    .into_bytes()
}

fn record_supervision(
    store: &Store,
    enrollment_id: &str,
    fingerprint: &str,
    udid: &str,
    supervised: bool,
    time: i64,
) -> Result<String> {
    let command_id = store.enqueue(
        enrollment_id,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".to_owned()],
        },
        &format!("device-information-{fingerprint}-{supervised}"),
        time,
    )?;
    let encoded = store
        .poll(fingerprint, &idle_response(udid)?, time + 1)?
        .ok_or_else(|| anyhow!("device information command was not dispatched"))?;
    let command = plist::Value::from_reader(Cursor::new(encoded))?;
    let dispatched_id = command
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("CommandUUID"))
        .and_then(plist::Value::as_string)
        .ok_or_else(|| anyhow!("dispatched command omitted CommandUUID"))?;
    assert_eq!(dispatched_id, command_id);
    let response = parse_response(&supervision_response_xml(udid, &command_id, supervised))?;
    assert!(store.poll(fingerprint, &response, time + 2)?.is_none());
    Ok(command_id)
}

#[test]
fn declarations_survive_sqlite_reopen_and_same_token_body_changes_are_rejected() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("ddm.sqlite");
    let store = Store::open(&database)?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-reopen", OLD_UDID, "18.0", BASE_TIME)?;
    let declaration = activation("activation-reopen", "token-one", "configuration-one");
    store.put_declaration(&declaration, BASE_TIME + 4)?;
    enable(&store, &enrollment_id, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    drop(store);

    let reopened = Store::open(&database)?;
    let response = request(
        &reopened,
        "fingerprint-reopen",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 7,
    )?
    .ok_or_else(|| anyhow!("declaration-items must return a body"))?;
    assert_eq!(
        declaration_items(&response)["Activations"][0]["Identifier"],
        "activation-reopen"
    );
    assert_eq!(
        declaration_items(&response)["Activations"][0]["ServerToken"],
        "token-one"
    );

    let changed_body = activation("activation-reopen", "token-one", "configuration-two");
    assert!(
        reopened
            .put_declaration(&changed_body, BASE_TIME + 8)
            .is_err()
    );
    let unchanged = request(
        &reopened,
        "fingerprint-reopen",
        OLD_UDID,
        "declaration/activation/activation-reopen",
        None,
        BASE_TIME + 9,
    )?
    .ok_or_else(|| anyhow!("declaration endpoint must return a body"))?;
    assert_eq!(unchanged["ServerToken"], "token-one");
    assert_eq!(
        unchanged["Payload"]["StandardConfigurations"][0],
        "configuration-one"
    );
    Ok(())
}

#[test]
fn manifest_tokens_follow_declaration_updates_deletes_and_target_replacements() -> Result<()> {
    let store = Store::memory()?;
    let first = active_enrollment(
        &store,
        "fingerprint-manifest-a",
        OLD_UDID,
        "18.0",
        BASE_TIME,
    )?;
    let second = active_enrollment(
        &store,
        "fingerprint-manifest-b",
        NEW_UDID,
        "18.0",
        BASE_TIME + 10,
    )?;
    enable(&store, &first, BASE_TIME + 20)?;
    enable(&store, &second, BASE_TIME + 21)?;
    let original = activation("activation-manifest", "token-one", "configuration-one");
    store.put_declaration(&original, BASE_TIME + 22)?;
    store.replace_declaration_targets(
        &original.identifier,
        std::slice::from_ref(&first),
        BASE_TIME + 23,
    )?;

    let first_manifest = request(
        &store,
        "fingerprint-manifest-a",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 24,
    )?
    .ok_or_else(|| anyhow!("first manifest must return a body"))?;
    assert_eq!(
        declaration_items(&first_manifest)["Activations"][0]["ServerToken"],
        "token-one"
    );

    let updated = activation("activation-manifest", "token-two", "configuration-two");
    store.put_declaration(&updated, BASE_TIME + 25)?;
    let updated_manifest = request(
        &store,
        "fingerprint-manifest-a",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 26,
    )?
    .ok_or_else(|| anyhow!("updated manifest must return a body"))?;
    assert_eq!(
        declaration_items(&updated_manifest)["Activations"][0]["ServerToken"],
        "token-two"
    );

    store.replace_declaration_targets(
        &updated.identifier,
        std::slice::from_ref(&second),
        BASE_TIME + 27,
    )?;
    let first_after_move = request(
        &store,
        "fingerprint-manifest-a",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 28,
    )?
    .ok_or_else(|| anyhow!("first moved manifest must return a body"))?;
    assert_eq!(
        declaration_items(&first_after_move)["Activations"],
        json!([])
    );
    let second_after_move = request(
        &store,
        "fingerprint-manifest-b",
        NEW_UDID,
        "declaration-items",
        None,
        BASE_TIME + 29,
    )?
    .ok_or_else(|| anyhow!("second moved manifest must return a body"))?;
    assert_eq!(
        declaration_items(&second_after_move)["Activations"][0]["ServerToken"],
        "token-two"
    );

    store.delete_declaration(&updated.identifier, &updated.server_token, BASE_TIME + 30)?;
    let second_after_delete = request(
        &store,
        "fingerprint-manifest-b",
        NEW_UDID,
        "declaration-items",
        None,
        BASE_TIME + 31,
    )?
    .ok_or_else(|| anyhow!("deleted manifest must return a body"))?;
    assert_eq!(
        declaration_items(&second_after_delete)["Activations"],
        json!([])
    );
    Ok(())
}

#[test]
fn equal_declaration_put_does_not_change_sync_tokens_or_persist_a_new_revision() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-equal", OLD_UDID, "18.0", BASE_TIME)?;
    enable(&store, &enrollment_id, BASE_TIME + 4)?;
    let declaration = activation("activation-equal", "token-equal", "configuration-equal");
    store.put_declaration(&declaration, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    let before = tokens(&store, "fingerprint-equal", OLD_UDID, BASE_TIME + 7)?;
    let declarations_before = store.declarations(None)?;
    store.put_declaration(&declaration, BASE_TIME + 8)?;
    let after = tokens(&store, "fingerprint-equal", OLD_UDID, BASE_TIME + 9)?;
    assert_eq!(before, after);
    assert_eq!(store.declarations(None)?.len(), declarations_before.len());
    assert_eq!(
        store.declarations(None)?[0].updated_at,
        declarations_before[0].updated_at
    );
    Ok(())
}

#[test]
fn declaration_update_and_delete_require_the_current_server_token() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-token", OLD_UDID, "18.0", BASE_TIME)?;
    let first = activation("activation-token", "token-one", "configuration-one");
    store.put_declaration(&first, BASE_TIME + 4)?;
    enable(&store, &enrollment_id, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &first.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    let second = activation("activation-token", "token-two", "configuration-two");
    store.put_declaration(&second, BASE_TIME + 7)?;
    assert!(
        store
            .delete_declaration(&first.identifier, &first.server_token, BASE_TIME + 8)
            .is_err()
    );
    store.delete_declaration(&second.identifier, &second.server_token, BASE_TIME + 9)?;
    let response = request(
        &store,
        "fingerprint-token",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 11,
    )?
    .ok_or_else(|| anyhow!("declaration-items must return a body"))?;
    assert_eq!(declaration_items(&response)["Activations"], json!([]));
    Ok(())
}

#[test]
fn ddm_rejects_unknown_targets_and_unsupported_os_versions() -> Result<()> {
    let store = Store::memory()?;
    let old_os = active_enrollment(&store, "fingerprint-old-os", OLD_UDID, "14.9", BASE_TIME)?;
    let declaration = activation("activation-os", "token-os", "configuration-os");
    store.put_declaration(&declaration, BASE_TIME + 4)?;
    assert!(enable(&store, &old_os, BASE_TIME + 5).is_err());
    assert!(
        store
            .replace_declaration_targets(
                &declaration.identifier,
                std::slice::from_ref(&old_os),
                BASE_TIME + 6,
            )
            .is_err()
    );
    let valid = active_enrollment(
        &store,
        "fingerprint-valid-os",
        NEW_UDID,
        "18.0",
        BASE_TIME + 10,
    )?;
    enable(&store, &valid, BASE_TIME + 11)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&valid),
        BASE_TIME + 12,
    )?;
    assert!(
        store
            .replace_declaration_targets(
                &declaration.identifier,
                &[valid.clone(), "missing-enrollment".to_owned()],
                BASE_TIME + 13,
            )
            .is_err()
    );
    assert!(
        request(
            &store,
            "fingerprint-old-os",
            OLD_UDID,
            "tokens",
            None,
            BASE_TIME + 14,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn required_app_managed_is_fail_closed_without_fresh_supervision() -> Result<()> {
    let store = Store::memory()?;
    let unknown = active_enrollment(
        &store,
        "fingerprint-app-managed-unknown",
        "00000000-0000-0000-0000-000000000003",
        "17.2",
        BASE_TIME,
    )?;
    let unknown_declaration = app_managed("app-managed-unknown", "token-unknown", "Required");
    store.put_declaration(&unknown_declaration, BASE_TIME + 4)?;
    enable(&store, &unknown, BASE_TIME + 5)?;
    assert!(
        store
            .replace_declaration_targets(
                &unknown_declaration.identifier,
                std::slice::from_ref(&unknown),
                BASE_TIME + 6,
            )
            .is_err()
    );

    let unsupervised = active_enrollment(
        &store,
        "fingerprint-app-managed-unsupervised",
        "00000000-0000-0000-0000-000000000004",
        "17.2",
        BASE_TIME + 10,
    )?;
    record_supervision(
        &store,
        &unsupervised,
        "fingerprint-app-managed-unsupervised",
        "00000000-0000-0000-0000-000000000004",
        false,
        BASE_TIME + 20,
    )?;
    let unsupervised_declaration =
        app_managed("app-managed-unsupervised", "token-unsupervised", "Required");
    store.put_declaration(&unsupervised_declaration, BASE_TIME + 21)?;
    enable(&store, &unsupervised, BASE_TIME + 22)?;
    assert!(
        store
            .replace_declaration_targets(
                &unsupervised_declaration.identifier,
                std::slice::from_ref(&unsupervised),
                BASE_TIME + 23,
            )
            .is_err()
    );

    let supervised = active_enrollment(
        &store,
        "fingerprint-app-managed-supervised",
        "00000000-0000-0000-0000-000000000005",
        "17.2",
        BASE_TIME + 30,
    )?;
    record_supervision(
        &store,
        &supervised,
        "fingerprint-app-managed-supervised",
        "00000000-0000-0000-0000-000000000005",
        true,
        BASE_TIME + 40,
    )?;
    let supervised_declaration =
        app_managed("app-managed-supervised", "token-supervised", "Required");
    store.put_declaration(&supervised_declaration, BASE_TIME + 41)?;
    enable(&store, &supervised, BASE_TIME + 42)?;
    store.replace_declaration_targets(
        &supervised_declaration.identifier,
        std::slice::from_ref(&supervised),
        BASE_TIME + 43,
    )?;
    let manifest = request(
        &store,
        "fingerprint-app-managed-supervised",
        "00000000-0000-0000-0000-000000000005",
        "declaration-items",
        None,
        BASE_TIME + 44,
    )?
    .ok_or_else(|| anyhow!("AppManaged declaration-items response missing"))?;
    assert_eq!(
        declaration_items(&manifest)["Configurations"][0]["Identifier"],
        "app-managed-supervised"
    );
    let fetched = request(
        &store,
        "fingerprint-app-managed-supervised",
        "00000000-0000-0000-0000-000000000005",
        "declaration/configuration/app-managed-supervised",
        None,
        BASE_TIME + 45,
    )?
    .ok_or_else(|| anyhow!("AppManaged declaration response missing"))?;
    assert_eq!(fetched["Type"], "com.apple.configuration.app.managed");
    Ok(())
}

#[test]
fn revoked_generation_is_unauthorized_and_new_generation_starts_empty() -> Result<()> {
    let store = Store::memory()?;
    let old = active_enrollment(
        &store,
        "fingerprint-generation-old",
        OLD_UDID,
        "18.0",
        BASE_TIME,
    )?;
    let declaration = activation(
        "activation-generation",
        "token-generation",
        "configuration-generation",
    );
    store.put_declaration(&declaration, BASE_TIME + 4)?;
    let old_command = enable(&store, &old, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&old),
        BASE_TIME + 6,
    )?;

    let new = active_enrollment(
        &store,
        "fingerprint-generation-new",
        OLD_UDID,
        "18.0",
        BASE_TIME + 10,
    )?;
    assert_eq!(store.command(&old_command)?.state, "cancelled");
    assert!(
        request(
            &store,
            "fingerprint-generation-old",
            OLD_UDID,
            "tokens",
            None,
            BASE_TIME + 14,
        )
        .is_err()
    );
    enable(&store, &new, BASE_TIME + 15)?;
    let response = request(
        &store,
        "fingerprint-generation-new",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 16,
    )?
    .ok_or_else(|| anyhow!("new generation must receive an empty manifest"))?;
    assert_eq!(declaration_items(&response)["Activations"], json!([]));
    Ok(())
}

#[test]
fn duplicate_and_late_status_reports_are_retained_without_claiming_declarations() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-status", OLD_UDID, "18.0", BASE_TIME)?;
    enable(&store, &enrollment_id, BASE_TIME + 4)?;
    let declaration = activation("activation-status", "token-status", "configuration-status");
    store.put_declaration(&declaration, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    let report = json!({
        "StatusItems": {"device.identifier.udid": OLD_UDID},
        "Errors": [],
        "FullReport": true
    });
    assert!(
        request(
            &store,
            "fingerprint-status",
            OLD_UDID,
            "status",
            Some(&report),
            BASE_TIME + 7,
        )?
        .is_none()
    );
    assert!(
        request(
            &store,
            "fingerprint-status",
            OLD_UDID,
            "status",
            Some(&report),
            BASE_TIME + 8,
        )?
        .is_none()
    );
    let reports = store.ddm_reports(&enrollment_id, 0)?;
    assert_eq!(
        reports.len(),
        1,
        "duplicate report must be digest-idempotent"
    );
    assert_eq!(
        reports[0]["report"]["StatusItems"]["device.identifier.udid"],
        OLD_UDID
    );

    let late = json!({
        "StatusItems": {"device.model.family": "iPad"},
        "Errors": [],
        "FullReport": false
    });
    request(
        &store,
        "fingerprint-status",
        OLD_UDID,
        "status",
        Some(&late),
        BASE_TIME - 1,
    )?;
    let reports = store.ddm_reports(&enrollment_id, 0)?;
    assert_eq!(reports.len(), 2, "late status must remain durable history");
    let view = store
        .declarations(None)?
        .into_iter()
        .find(|view| view.declaration.identifier == declaration.identifier)
        .ok_or_else(|| anyhow!("status report removed a declaration"))?;
    assert!(
        !view.deleted,
        "status report must not claim or delete a declaration"
    );
    Ok(())
}

#[test]
fn declarative_management_timeout_becomes_outcome_unknown_without_blind_resend() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-timeout", OLD_UDID, "18.0", BASE_TIME)?;
    let command_id = enable(&store, &enrollment_id, BASE_TIME + 4)?;
    let idle = idle_response(OLD_UDID)?;
    assert!(
        store
            .poll("fingerprint-timeout", &idle, BASE_TIME + 5)?
            .is_some()
    );
    assert_eq!(store.command(&command_id)?.state, "awaiting_response");
    assert_eq!(
        store.recover_timeouts(BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 6)?,
        1
    );
    assert_eq!(store.command(&command_id)?.state, "outcome_unknown");
    assert!(
        store
            .poll(
                "fingerprint-timeout",
                &idle,
                BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 7
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn declarative_management_coexists_with_install_and_remove_profile_commands() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-coexist", OLD_UDID, "18.0", BASE_TIME)?;
    let ddm_command = enable(&store, &enrollment_id, BASE_TIME + 4)?;
    let install_command = store.enqueue(
        &enrollment_id,
        &install_profile(),
        "ddm-install",
        BASE_TIME + 5,
    )?;
    let remove_command = store.enqueue(
        &enrollment_id,
        &remove_profile(),
        "ddm-remove",
        BASE_TIME + 6,
    )?;
    let idle = idle_response(OLD_UDID)?;
    assert!(
        store
            .poll("fingerprint-coexist", &idle, BASE_TIME + 7)?
            .is_some()
    );
    assert_eq!(store.command(&ddm_command)?.state, "awaiting_response");
    assert_eq!(store.command(&install_command)?.state, "queued");
    assert_eq!(store.command(&remove_command)?.state, "queued");

    let ddm_ack = acknowledged_response(OLD_UDID, &ddm_command)?;
    assert!(
        store
            .poll("fingerprint-coexist", &ddm_ack, BASE_TIME + 8)?
            .is_some()
    );
    assert_eq!(store.command(&ddm_command)?.state, "completed");
    assert_eq!(store.command(&install_command)?.state, "awaiting_response");
    assert_eq!(store.command(&remove_command)?.state, "queued");

    let install_ack = acknowledged_response(OLD_UDID, &install_command)?;
    assert!(
        store
            .poll("fingerprint-coexist", &install_ack, BASE_TIME + 9)?
            .is_some()
    );
    assert_eq!(store.command(&install_command)?.state, "completed");
    assert_eq!(store.command(&remove_command)?.state, "awaiting_response");

    let remove_ack = acknowledged_response(OLD_UDID, &remove_command)?;
    assert!(
        store
            .poll("fingerprint-coexist", &remove_ack, BASE_TIME + 10)?
            .is_none()
    );
    assert_eq!(store.command(&remove_command)?.state, "completed");
    Ok(())
}

#[test]
fn declaration_mutation_and_ddm_outbox_are_atomic_when_queue_is_full() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(
        &store,
        "fingerprint-queue-full",
        OLD_UDID,
        "18.0",
        BASE_TIME,
    )?;
    let first = activation("activation-queue-full", "token-one", "configuration-one");
    store.put_declaration(&first, BASE_TIME + 4)?;
    let ddm_command = enable(&store, &enrollment_id, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &first.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    let idle = idle_response(OLD_UDID)?;
    assert!(
        store
            .poll("fingerprint-queue-full", &idle, BASE_TIME + 7)?
            .is_some()
    );
    assert_eq!(store.command(&ddm_command)?.state, "awaiting_response");
    let before_tokens = tokens(&store, "fingerprint-queue-full", OLD_UDID, BASE_TIME + 8)?;
    for index in 0..255 {
        store.enqueue(
            &enrollment_id,
            &device_information(),
            &format!("queue-full-{index}"),
            BASE_TIME + 8 + index,
        )?;
    }
    let updated = activation("activation-queue-full", "token-two", "configuration-two");
    assert!(store.put_declaration(&updated, BASE_TIME + 300).is_err());
    assert_eq!(store.command(&ddm_command)?.state, "awaiting_response");

    let view = store
        .declarations(None)?
        .into_iter()
        .find(|view| view.declaration.identifier == first.identifier)
        .ok_or_else(|| anyhow!("declaration disappeared after rollback"))?;
    assert_eq!(view.declaration.server_token, "token-one");
    assert_eq!(
        view.declaration.payload["StandardConfigurations"][0],
        "configuration-one"
    );
    let manifest = request(
        &store,
        "fingerprint-queue-full",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 301,
    )?
    .ok_or_else(|| anyhow!("manifest must remain available after rollback"))?;
    assert_eq!(
        declaration_items(&manifest)["Activations"][0]["ServerToken"],
        "token-one"
    );
    let sync_tokens = tokens(&store, "fingerprint-queue-full", OLD_UDID, BASE_TIME + 302)?;
    assert_eq!(
        sync_tokens["SyncTokens"]["DeclarationsToken"],
        before_tokens["SyncTokens"]["DeclarationsToken"]
    );
    Ok(())
}

#[test]
fn replacing_targets_rolls_back_when_one_target_conflicts() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id =
        active_enrollment(&store, "fingerprint-atomic", OLD_UDID, "18.0", BASE_TIME)?;
    let declaration = activation("activation-atomic", "token-atomic", "configuration-atomic");
    store.put_declaration(&declaration, BASE_TIME + 4)?;
    enable(&store, &enrollment_id, BASE_TIME + 5)?;
    store.replace_declaration_targets(
        &declaration.identifier,
        std::slice::from_ref(&enrollment_id),
        BASE_TIME + 6,
    )?;
    assert!(
        store
            .replace_declaration_targets(
                &declaration.identifier,
                &[enrollment_id.clone(), "conflicting-target".to_owned()],
                BASE_TIME + 7,
            )
            .is_err()
    );
    let response = request(
        &store,
        "fingerprint-atomic",
        OLD_UDID,
        "declaration-items",
        None,
        BASE_TIME + 9,
    )?
    .ok_or_else(|| anyhow!("declaration-items must return a body"))?;
    assert_eq!(
        declaration_items(&response)["Activations"][0]["Identifier"],
        "activation-atomic"
    );
    Ok(())
}

#[test]
fn schema_one_database_migrates_to_ddm_schema_and_restores_legacy_rows() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("legacy.sqlite");
    let legacy_id = "legacy-enrollment";
    let legacy_challenge = "legacy-challenge";
    let legacy_time = BASE_TIME;
    let connection = Connection::open(&database)?;
    connection.execute_batch(include_str!("../migrations/001_initial.sql"))?;
    connection.execute(
        "INSERT INTO enrollments(id,state,challenge_hash,challenge_expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        params![
            legacy_id,
            "pending",
            digest(legacy_challenge.as_bytes()),
            legacy_time + 900,
            legacy_time,
            legacy_time,
        ],
    )?;
    connection.execute(
        "INSERT INTO audit(happened_at,actor,action,resource_id) VALUES(?,?,?,?)",
        params![legacy_time, "admin", "legacy_fixture", legacy_id],
    )?;
    drop(connection);
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
    }

    let store = Store::open(&database)?;
    let enrollments = store.enrollments(None)?;
    assert_eq!(enrollments.len(), 1);
    assert_eq!(enrollments[0].id, legacy_id);
    assert_eq!(enrollments[0].state, "pending");
    let audits = store.audits(0)?;
    assert!(
        audits.iter().any(|entry| {
            entry["action"] == "legacy_fixture" && entry["resource_id"] == legacy_id
        })
    );

    let backup = directory.path().join("legacy-backup.sqlite");
    store.backup(&backup)?;
    let backup_info = validate_backup(&backup)?;
    assert_eq!(backup_info.user_version, 3);

    let restored = directory.path().join("restored/legacy.sqlite");
    let restored_info = restore_database(&backup, &restored)?;
    assert_eq!(restored_info.user_version, 3);
    let reopened = Store::open(&restored)?;
    let restored_enrollments = reopened.enrollments(None)?;
    assert_eq!(restored_enrollments.len(), 1);
    assert_eq!(restored_enrollments[0].id, legacy_id);
    assert_eq!(restored_enrollments[0].state, "pending");
    Ok(())
}
