use anyhow::{Context, Result, anyhow};
use mdm_protocol::{
    CheckIn, CommandPayload, DeviceResponse, OsInstallAction, OsUpdate, parse_checkin,
    parse_response,
};
use mdmd::{
    recovery::{restore_database, validate_backup},
    storage::{IssuedCertificate, RESPONSE_TIMEOUT_SECONDS, Store},
};
use rusqlite::Connection;
use serde_json::json;
use std::{
    fs,
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
};
use tempfile::tempdir;

const BASE_TIME: i64 = 1_800_000_000;
const TOPIC: &str = "com.apple.mgmt.operations-test";

fn authenticate_xml(udid: &str, serial: &str, os_version: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string>
<key>UDID</key><string>{udid}</string>
<key>Topic</key><string>{TOPIC}</string>
<key>SerialNumber</key><string>{serial}</string>
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

fn response_xml(udid: &str, command_uuid: &str, body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>Acknowledged</string>
<key>CommandUUID</key><string>{command_uuid}</string>
{body}
</dict></plist>"#
    )
    .into_bytes()
}

fn idle_response(udid: &str) -> Result<DeviceResponse> {
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>Idle</string>
</dict></plist>"#
    );
    Ok(parse_response(body.as_bytes())?)
}

fn acknowledged_response(udid: &str, command_id: &str, body: &str) -> Result<DeviceResponse> {
    Ok(parse_response(&response_xml(udid, command_id, body))?)
}

fn active_enrollment(
    store: &Store,
    fingerprint: &str,
    udid: &str,
    serial: &str,
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

    let authenticate = parse_checkin(&authenticate_xml(udid, serial, os_version))?;
    assert!(matches!(authenticate, CheckIn::Authenticate { .. }));
    store.checkin(fingerprint, &authenticate, time + 2)?;
    let token_update = parse_checkin(&token_update_xml(udid))?;
    assert!(matches!(token_update, CheckIn::TokenUpdate { .. }));
    store.checkin(fingerprint, &token_update, time + 3)?;
    let enrollment = store
        .enrollments(None)?
        .into_iter()
        .find(|view| view.id == enrollment_id)
        .ok_or_else(|| anyhow!("enrollment disappeared"))?;
    assert_eq!(enrollment.state, "active");
    assert_eq!(enrollment.serial_number.as_deref(), Some(serial));
    Ok(enrollment_id)
}

fn dispatch(store: &Store, fingerprint: &str, udid: &str, time: i64) -> Result<Vec<u8>> {
    store
        .poll(fingerprint, &idle_response(udid)?, time)?
        .ok_or_else(|| anyhow!("expected a command to be dispatched"))
}

fn acknowledge(
    store: &Store,
    fingerprint: &str,
    udid: &str,
    command_id: &str,
    body: &str,
    time: i64,
) -> Result<()> {
    let response = acknowledged_response(udid, command_id, body)?;
    store.poll(fingerprint, &response, time)?;
    Ok(())
}

fn request_type(bytes: &[u8]) -> Result<String> {
    let value = plist::Value::from_reader(Cursor::new(bytes))?;
    let root = value
        .as_dictionary()
        .context("command is not a plist dictionary")?;
    let command = root
        .get("Command")
        .and_then(plist::Value::as_dictionary)
        .unwrap_or(root);
    Ok(command
        .get("RequestType")
        .and_then(plist::Value::as_string)
        .unwrap_or_default()
        .to_owned())
}

#[test]
fn enrollment_observations_capture_supervision_and_application_inventory() -> Result<()> {
    let store = Store::memory()?;
    let enrollment = active_enrollment(
        &store,
        "operations-observations-cert",
        "00000000-0000-0000-0000-000000000101",
        "OPS-SERIAL-101",
        "18.0",
        BASE_TIME,
    )?;

    let info = CommandPayload::DeviceInformation {
        queries: vec![
            "IsSupervised".into(),
            "OSVersion".into(),
            "SerialNumber".into(),
        ],
    };
    let info_id = store.enqueue(&enrollment, &info, "operations-info", BASE_TIME + 4)?;
    let info_wire = dispatch(
        &store,
        "operations-observations-cert",
        "00000000-0000-0000-0000-000000000101",
        BASE_TIME + 5,
    )?;
    assert_eq!(request_type(&info_wire)?, "DeviceInformation");
    acknowledge(
        &store,
        "operations-observations-cert",
        "00000000-0000-0000-0000-000000000101",
        &info_id,
        r#"<key>QueryResponses</key><dict>
<key>IsSupervised</key><true/>
<key>OSVersion</key><string>18.0</string>
<key>SerialNumber</key><string>OPS-SERIAL-101</string>
</dict>"#,
        BASE_TIME + 6,
    )?;
    assert_eq!(store.command(&info_id)?.state, "completed");

    let installed = CommandPayload::InstalledApplicationList {
        identifiers: Some(vec!["com.example.managed".into()]),
        managed_apps_only: false,
        items: None,
    };
    let installed_id = store.enqueue(
        &enrollment,
        &installed,
        "operations-installed",
        BASE_TIME + 7,
    )?;
    let installed_wire = dispatch(
        &store,
        "operations-observations-cert",
        "00000000-0000-0000-0000-000000000101",
        BASE_TIME + 8,
    )?;
    assert_eq!(request_type(&installed_wire)?, "InstalledApplicationList");
    acknowledge(
        &store,
        "operations-observations-cert",
        "00000000-0000-0000-0000-000000000101",
        &installed_id,
        r#"<key>InstalledApplicationList</key><array><dict>
<key>Identifier</key><string>com.example.managed</string>
<key>Installing</key><false/>
</dict></array>"#,
        BASE_TIME + 9,
    )?;

    let observations = store.observations(&enrollment)?;
    let info_observation = observations
        .iter()
        .find(|observation| observation.category == "device_information")
        .context("device information observation missing")?;
    assert_eq!(
        info_observation.body["QueryResponses"]["IsSupervised"],
        true
    );
    let apps_observation = observations
        .iter()
        .find(|observation| observation.category == "installed_applications")
        .context("installed application observation missing")?;
    assert_eq!(
        apps_observation.body["InstalledApplicationList"][0]["Identifier"],
        "com.example.managed"
    );
    Ok(())
}

#[test]
fn kiosk_requires_supervised_and_fresh_installed_application_evidence() -> Result<()> {
    let store = Store::memory()?;
    let unsupervised = active_enrollment(
        &store,
        "operations-kiosk-unsupervised",
        "00000000-0000-0000-0000-000000000102",
        "OPS-SERIAL-102",
        "18.0",
        BASE_TIME,
    )?;
    let info_id = store.enqueue(
        &unsupervised,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "kiosk-unsupervised-info",
        BASE_TIME + 4,
    )?;
    dispatch(
        &store,
        "operations-kiosk-unsupervised",
        "00000000-0000-0000-0000-000000000102",
        BASE_TIME + 5,
    )?;
    acknowledge(
        &store,
        "operations-kiosk-unsupervised",
        "00000000-0000-0000-0000-000000000102",
        &info_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><false/></dict>"#,
        BASE_TIME + 6,
    )?;
    let installed_id = store.enqueue(
        &unsupervised,
        &CommandPayload::InstalledApplicationList {
            identifiers: Some(vec!["com.example.kiosk".into()]),
            managed_apps_only: false,
            items: None,
        },
        "kiosk-unsupervised-installed",
        BASE_TIME + 7,
    )?;
    dispatch(
        &store,
        "operations-kiosk-unsupervised",
        "00000000-0000-0000-0000-000000000102",
        BASE_TIME + 8,
    )?;
    acknowledge(
        &store,
        "operations-kiosk-unsupervised",
        "00000000-0000-0000-0000-000000000102",
        &installed_id,
        r#"<key>InstalledApplicationList</key><array><dict><key>Identifier</key><string>com.example.kiosk</string><key>Installing</key><false/></dict></array>"#,
        BASE_TIME + 9,
    )?;
    assert!(
        store
            .apply_kiosk(
                &unsupervised,
                "com.example.kiosk",
                "kiosk-unsafe",
                BASE_TIME + 10
            )
            .is_err()
    );

    let supervised = active_enrollment(
        &store,
        "operations-kiosk-supervised",
        "00000000-0000-0000-0000-000000000103",
        "OPS-SERIAL-103",
        "18.0",
        BASE_TIME + 20,
    )?;
    let info_id = store.enqueue(
        &supervised,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "kiosk-supervised-info",
        BASE_TIME + 24,
    )?;
    dispatch(
        &store,
        "operations-kiosk-supervised",
        "00000000-0000-0000-0000-000000000103",
        BASE_TIME + 25,
    )?;
    acknowledge(
        &store,
        "operations-kiosk-supervised",
        "00000000-0000-0000-0000-000000000103",
        &info_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><true/></dict>"#,
        BASE_TIME + 26,
    )?;
    let installed_id = store.enqueue(
        &supervised,
        &CommandPayload::InstalledApplicationList {
            identifiers: Some(vec!["com.example.kiosk".into()]),
            managed_apps_only: false,
            items: None,
        },
        "kiosk-supervised-installed",
        BASE_TIME + 27,
    )?;
    dispatch(
        &store,
        "operations-kiosk-supervised",
        "00000000-0000-0000-0000-000000000103",
        BASE_TIME + 28,
    )?;
    acknowledge(
        &store,
        "operations-kiosk-supervised",
        "00000000-0000-0000-0000-000000000103",
        &installed_id,
        r#"<key>InstalledApplicationList</key><array><dict><key>Identifier</key><string>com.example.kiosk</string><key>Installing</key><false/></dict></array>"#,
        BASE_TIME + 29,
    )?;

    let kiosk_id = store.apply_kiosk(
        &supervised,
        "com.example.kiosk",
        "kiosk-apply",
        BASE_TIME + 30,
    )?;
    assert_eq!(
        store.apply_kiosk(
            &supervised,
            "com.example.kiosk",
            "kiosk-apply",
            BASE_TIME + 31,
        )?,
        kiosk_id
    );
    let release_id = store.release_kiosk(&supervised, "kiosk-release", BASE_TIME + 32)?;
    assert_ne!(release_id, kiosk_id);
    assert_eq!(store.command(&kiosk_id)?.kind, "install_profile");
    assert_eq!(store.command(&release_id)?.kind, "remove_profile");
    Ok(())
}

#[test]
fn os_update_queries_are_observed_and_schedule_requires_supervision() -> Result<()> {
    let store = Store::memory()?;
    let enrollment = active_enrollment(
        &store,
        "operations-os-cert",
        "00000000-0000-0000-0000-000000000104",
        "OPS-SERIAL-104",
        "18.0",
        BASE_TIME,
    )?;
    let info_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "os-info",
        BASE_TIME + 4,
    )?;
    dispatch(
        &store,
        "operations-os-cert",
        "00000000-0000-0000-0000-000000000104",
        BASE_TIME + 5,
    )?;
    acknowledge(
        &store,
        "operations-os-cert",
        "00000000-0000-0000-0000-000000000104",
        &info_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><true/></dict>"#,
        BASE_TIME + 6,
    )?;

    let available_id = store.enqueue(
        &enrollment,
        &CommandPayload::AvailableOSUpdates,
        "os-available",
        BASE_TIME + 7,
    )?;
    let available_wire = dispatch(
        &store,
        "operations-os-cert",
        "00000000-0000-0000-0000-000000000104",
        BASE_TIME + 8,
    )?;
    assert_eq!(request_type(&available_wire)?, "AvailableOSUpdates");
    acknowledge(
        &store,
        "operations-os-cert",
        "00000000-0000-0000-0000-000000000104",
        &available_id,
        r#"<key>AvailableOSUpdates</key><array><dict><key>ProductKey</key><string>iOS-18.0</string></dict></array>"#,
        BASE_TIME + 9,
    )?;

    let schedule_id = store.enqueue(
        &enrollment,
        &CommandPayload::ScheduleOSUpdate {
            updates: vec![OsUpdate {
                product_key: Some("iOS-18.0".into()),
                product_version: Some("18.0".into()),
                install_action: OsInstallAction::Default,
                max_user_deferrals: None,
                priority: None,
            }],
        },
        "os-schedule",
        BASE_TIME + 10,
    )?;
    assert_eq!(store.command(&schedule_id)?.kind, "schedule_os_update");
    let observations = store.observations(&enrollment)?;
    assert!(
        observations
            .iter()
            .any(|observation| observation.category == "available_os_updates")
    );
    Ok(())
}

#[test]
fn read_only_timeouts_retry_with_the_same_command_and_mutations_become_unknown() -> Result<()> {
    let store = Store::memory()?;
    let enrollment = active_enrollment(
        &store,
        "operations-timeout-cert",
        "00000000-0000-0000-0000-000000000105",
        "OPS-SERIAL-105",
        "18.0",
        BASE_TIME,
    )?;
    let read_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["DeviceName".into()],
        },
        "timeout-read",
        BASE_TIME + 4,
    )?;
    dispatch(
        &store,
        "operations-timeout-cert",
        "00000000-0000-0000-0000-000000000105",
        BASE_TIME + 5,
    )?;
    assert_eq!(
        store.recover_timeouts(BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 6)?,
        1
    );
    assert_eq!(store.command(&read_id)?.state, "queued");
    let second_wire = dispatch(
        &store,
        "operations-timeout-cert",
        "00000000-0000-0000-0000-000000000105",
        BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 7,
    )?;
    assert_eq!(request_type(&second_wire)?, "DeviceInformation");
    assert_eq!(store.command(&read_id)?.attempt_count, 2);

    let mutation_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceLock {
            message: Some("Operations test".into()),
            phone_number: None,
            pin: None,
        },
        "timeout-mutation",
        BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 8,
    )?;
    // The read command is still in flight, so finish it before dispatching the mutation.
    let mutation_wire = store
        .poll(
            "operations-timeout-cert",
            &acknowledged_response("00000000-0000-0000-0000-000000000105", &read_id, "")?,
            BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 9,
        )?
        .ok_or_else(|| anyhow!("mutation was not dispatched after the read reply"))?;
    assert_eq!(request_type(&mutation_wire)?, "DeviceLock");
    assert_eq!(
        store.recover_timeouts(BASE_TIME + 2 * RESPONSE_TIMEOUT_SECONDS + 11)?,
        1
    );
    assert_eq!(store.command(&mutation_id)?.state, "outcome_unknown");
    assert!(
        store
            .poll(
                "operations-timeout-cert",
                &idle_response("00000000-0000-0000-0000-000000000105")?,
                BASE_TIME + 2 * RESPONSE_TIMEOUT_SECONDS + 12,
            )?
            .is_none()
    );

    let body = json!({"adam_id":"123","serial_number":"OPS-SERIAL-105","assign":true});
    assert!(
        store
            .reserve_apple_request("vpp-timeout", "license_assign", &body, BASE_TIME)?
            .is_none()
    );
    let pending = store
        .reserve_apple_request("vpp-timeout", "license_assign", &body, BASE_TIME + 1)?
        .context("pending Apps & Books mutation was not retained")?;
    assert_eq!(pending.state, "outcome_unknown");
    store.finish_apple_request("vpp-timeout", &json!({"accepted":true}), BASE_TIME + 2)?;
    let completed = store
        .reserve_apple_request("vpp-timeout", "license_assign", &body, BASE_TIME + 3)?
        .context("completed Apps & Books mutation was not retained")?;
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.result, Some(json!({"accepted":true})));
    assert!(
        store
            .reserve_apple_request(
                "vpp-timeout",
                "license_assign",
                &json!({"adam_id":"123","serial_number":"OTHER","assign":true}),
                BASE_TIME + 4,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn erase_requires_two_phase_serial_confirmation_and_generation_isolation() -> Result<()> {
    let store = Store::memory()?;
    let enrollment = active_enrollment(
        &store,
        "operations-erase-cert",
        "00000000-0000-0000-0000-000000000106",
        "OPS-SERIAL-106",
        "18.0",
        BASE_TIME,
    )?;
    let destructive = CommandPayload::EraseDevice {
        preserve_data_plan: false,
        disallow_proximity_setup: true,
        pin: None,
        obliteration_behavior: None,
    };
    assert!(
        store
            .enqueue(&enrollment, &destructive, "erase-generic", BASE_TIME + 4)
            .is_err()
    );

    let intent = store.prepare_erase(&enrollment, BASE_TIME + 5)?;
    assert_eq!(intent.serial_number, "OPS-SERIAL-106");
    assert_eq!(intent.expires_at, BASE_TIME + 305);
    assert!(
        store
            .confirm_erase(
                &enrollment,
                &intent.id,
                "wrong-token",
                &intent.serial_number,
                "erase-key",
                BASE_TIME + 6,
            )
            .is_err()
    );
    assert!(
        store
            .confirm_erase(
                &enrollment,
                &intent.id,
                &intent.token,
                "WRONG-SERIAL",
                "erase-key",
                BASE_TIME + 6,
            )
            .is_err()
    );
    let command_id = store.confirm_erase(
        &enrollment,
        &intent.id,
        &intent.token,
        &intent.serial_number,
        "erase-key",
        BASE_TIME + 7,
    )?;
    assert_eq!(
        store.confirm_erase(
            &enrollment,
            &intent.id,
            &intent.token,
            &intent.serial_number,
            "erase-key",
            BASE_TIME + 8,
        )?,
        command_id
    );
    assert!(
        store
            .confirm_erase(
                &enrollment,
                &intent.id,
                &intent.token,
                &intent.serial_number,
                "different-key",
                BASE_TIME + 9,
            )
            .is_err()
    );

    let isolated = Store::memory()?;
    let old = active_enrollment(
        &isolated,
        "operations-erase-old",
        "00000000-0000-0000-0000-000000000107",
        "OPS-SERIAL-107",
        "18.0",
        BASE_TIME,
    )?;
    let old_intent = isolated.prepare_erase(&old, BASE_TIME + 5)?;
    let new = active_enrollment(
        &isolated,
        "operations-erase-new",
        "00000000-0000-0000-0000-000000000107",
        "OPS-SERIAL-107",
        "18.0",
        BASE_TIME + 20,
    )?;
    assert_ne!(old, new);
    assert!(
        isolated
            .confirm_erase(
                &old,
                &old_intent.id,
                &old_intent.token,
                &old_intent.serial_number,
                "old-generation-key",
                BASE_TIME + 21,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn operation_rows_survive_schema_three_backup_and_restore() -> Result<()> {
    let directory = tempdir()?;
    let source = directory.path().join("mdm.sqlite");
    let backup = directory.path().join("mdm-backup.sqlite");
    let restored = directory.path().join("restored.sqlite");
    let store = Store::open(&source)?;
    let enrollment = active_enrollment(
        &store,
        "operations-backup-cert",
        "00000000-0000-0000-0000-000000000108",
        "OPS-SERIAL-108",
        "18.0",
        BASE_TIME,
    )?;
    store.save_ade_devices(
        &[json!({
            "serial_number":"OPS-SERIAL-108",
            "profile_uuid":"00000000-0000-0000-0000-000000000109",
            "op_type":"added"
        })],
        BASE_TIME + 4,
    )?;
    store.save_license_event(
        123,
        "OPS-SERIAL-108",
        &json!({"event":"assigned","adam_id":"123"}),
        BASE_TIME + 5,
    )?;
    let apple_body = json!({"adam_id":"123","serial_number":"OPS-SERIAL-108"});
    assert!(
        store
            .reserve_apple_request("backup-vpp", "license_assign", &apple_body, BASE_TIME + 6)?
            .is_none()
    );
    store.finish_apple_request("backup-vpp", &json!({"accepted":true}), BASE_TIME + 7)?;
    let observation_command = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["DeviceName".into()],
        },
        "backup-observation-command",
        BASE_TIME + 8,
    )?;
    dispatch(
        &store,
        "operations-backup-cert",
        "00000000-0000-0000-0000-000000000108",
        BASE_TIME + 9,
    )?;
    acknowledge(
        &store,
        "operations-backup-cert",
        "00000000-0000-0000-0000-000000000108",
        &observation_command,
        r#"<key>QueryResponses</key><dict><key>DeviceName</key><string>Operations Test</string></dict>"#,
        BASE_TIME + 10,
    )?;

    store.backup(&backup)?;
    let info = validate_backup(&backup)?;
    assert_eq!(info.user_version, 3);
    assert_eq!(restore_database(&backup, &restored)?, info);
    let restored_store = Store::open(&restored)?;
    assert_eq!(restored_store.ade_devices()?.len(), 1);
    assert_eq!(
        restored_store.license_event(123, "OPS-SERIAL-108")?["event"],
        "assigned"
    );
    let request = restored_store
        .reserve_apple_request("backup-vpp", "license_assign", &apple_body, BASE_TIME + 11)?
        .context("restored Apple request missing")?;
    assert_eq!(request.state, "completed");
    assert_eq!(restored_store.observations(&enrollment)?.len(), 1);
    Ok(())
}

fn create_schema_two_database(path: &Path) -> Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch(include_str!("../migrations/001_initial.sql"))?;
    connection.execute_batch(include_str!("../migrations/002_ddm.sql"))?;
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[test]
fn schema_two_default_rights_reject_new_application_and_lock_operations() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("schema-two.sqlite");
    create_schema_two_database(&database)?;
    let store = Store::open(&database)?;
    let enrollment = active_enrollment(
        &store,
        "operations-schema-two-cert",
        "00000000-0000-0000-0000-000000000110",
        "OPS-SERIAL-110",
        "18.0",
        BASE_TIME,
    )?;
    drop(store);
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE enrollments SET mdm_access_rights=19 WHERE id=?",
        [&enrollment],
    )?;
    drop(connection);
    let store = Store::open(&database)?;
    assert!(
        store
            .enqueue(
                &enrollment,
                &CommandPayload::InstallApplication {
                    source: mdm_protocol::ApplicationInstallSource::AppStore {
                        itunes_store_id: 123,
                        purchase_method: 1,
                    },
                },
                "schema-two-app",
                BASE_TIME + 10,
            )
            .is_err()
    );
    assert!(
        store
            .enqueue(
                &enrollment,
                &CommandPayload::DeviceLock {
                    message: None,
                    phone_number: None,
                    pin: None,
                },
                "schema-two-lock",
                BASE_TIME + 11,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn ade_bootstrap_requires_assignment_binds_signed_identity_and_replays_safely() -> Result<()> {
    let store = Store::memory()?;
    let serial = "ADE-SERIAL-001";
    let udid = "00000000-0000-0000-0000-000000000111";
    let profile = json!({
        "profile_name": "Operations ADE profile",
        "url": "https://mdm.example.test/ade/enroll"
    });
    store.save_ade_profile("p", &profile)?;

    // A serial that is absent, then present but unassigned, cannot bootstrap.
    assert!(
        store
            .ade_bootstrap(serial, udid, "proof-1", BASE_TIME, |_id, _challenge| {
                Ok(b"must-not-be-created".to_vec())
            })
            .is_err()
    );
    store.save_ade_devices(
        &[json!({
            "serial_number": serial,
            "profile_uuid": "p",
            "profile_status": "unassigned",
            "op_type": "added"
        })],
        BASE_TIME + 1,
    )?;
    assert!(
        store
            .ade_bootstrap(serial, udid, "proof-1", BASE_TIME + 2, |_id, _challenge| {
                Ok(b"must-not-be-created".to_vec())
            })
            .is_err()
    );
    store.save_ade_devices(
        &[json!({
            "serial_number": serial,
            "profile_uuid": "p",
            "profile_status": "assigned",
            "op_type": "added"
        })],
        BASE_TIME + 3,
    )?;

    let captured = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let captured_for_profile = Arc::clone(&captured);
    let first_profile = store.ade_bootstrap(
        serial,
        udid,
        "proof-1",
        BASE_TIME + 4,
        move |enrollment_id, challenge| {
            captured_for_profile
                .lock()
                .map_err(|_| anyhow!("profile capture lock poisoned"))?
                .push((enrollment_id.to_owned(), challenge.to_owned()));
            Ok(b"ade-profile-v1".to_vec())
        },
    )?;
    assert_eq!(first_profile, b"ade-profile-v1".to_vec());
    let first_capture = captured
        .lock()
        .map_err(|_| anyhow!("profile capture lock poisoned"))?
        .first()
        .cloned()
        .context("ADE profile closure was not called")?;
    assert!(!first_capture.0.is_empty());
    assert!(!first_capture.1.is_empty());

    // An identical signed proof is a cache hit and must not create a second
    // enrollment or invoke the profile generator again.
    let replay =
        store.ade_bootstrap(serial, udid, "proof-1", BASE_TIME + 5, |_id, _challenge| {
            Err(anyhow!("replay must use the cached profile"))
        })?;
    assert_eq!(replay, first_profile);
    assert_eq!(captured.lock().unwrap().len(), 1);
    assert_eq!(store.enrollments(None)?.len(), 1);
    assert!(
        store
            .ade_bootstrap(
                serial,
                udid,
                "different-proof",
                BASE_TIME + 6,
                |_id, _challenge| { Err(anyhow!("different proof must not create a profile")) }
            )
            .is_err()
    );
    assert!(
        store
            .ade_bootstrap(
                serial,
                udid,
                "proof-1",
                BASE_TIME + 904,
                |_id, _challenge| { Err(anyhow!("expired proof must not create a profile")) }
            )
            .is_err()
    );

    // The profile challenge is the only value needed to exercise SCEP. The
    // expected serial and UDID are checked before the enrollment becomes
    // usable, so mismatched Authenticate messages remain unauthorized.
    let issued = store.issue_identity(
        &first_capture.1,
        "ade-csr-proof-1",
        BASE_TIME + 10,
        |enrollment_id| {
            assert_eq!(enrollment_id, first_capture.0);
            Ok(IssuedCertificate {
                fingerprint: "ade-device-cert-1".into(),
                expires_at: "2035-01-01T00:00:00Z".into(),
                response: b"ade-cert-response-1".to_vec(),
            })
        },
    )?;
    assert_eq!(issued, b"ade-cert-response-1".to_vec());
    let wrong_serial = parse_checkin(&authenticate_xml(udid, "ADE-WRONG", "18.0"))?;
    assert!(
        store
            .checkin("ade-device-cert-1", &wrong_serial, BASE_TIME + 11)
            .is_err()
    );
    let wrong_udid = parse_checkin(&authenticate_xml(
        "00000000-0000-0000-0000-000000000112",
        serial,
        "18.0",
    ))?;
    assert!(
        store
            .checkin("ade-device-cert-1", &wrong_udid, BASE_TIME + 11)
            .is_err()
    );
    let authenticate = parse_checkin(&authenticate_xml(udid, serial, "18.0"))?;
    store.checkin("ade-device-cert-1", &authenticate, BASE_TIME + 11)?;
    let token = parse_checkin(&token_update_xml(udid))?;
    store.checkin("ade-device-cert-1", &token, BASE_TIME + 12)?;
    assert_eq!(
        store
            .enrollments(None)?
            .into_iter()
            .find(|view| view.id == first_capture.0)
            .context("ADE enrollment disappeared")?
            .state,
        "active"
    );

    // A new generation with the same UDID revokes the old identity. A replay
    // for the revoked generation must not hand out its cached ADE profile.
    let replacement = active_enrollment(
        &store,
        "ade-replacement-cert",
        udid,
        serial,
        "18.0",
        BASE_TIME + 20,
    )?;
    assert_ne!(replacement, first_capture.0);
    assert!(
        store
            .ade_bootstrap(
                serial,
                udid,
                "proof-1",
                BASE_TIME + 23,
                |_id, _challenge| {
                    Err(anyhow!("revoked generation must not replay its profile"))
                }
            )
            .is_err()
    );

    // An explicit administrative reset permits a fresh Apple proof and a new
    // enrollment generation for the same serial.
    store.reset_ade_bootstrap(serial, BASE_TIME + 24)?;
    let captured_for_second = Arc::clone(&captured);
    let second_profile = store.ade_bootstrap(
        serial,
        udid,
        "proof-2",
        BASE_TIME + 25,
        move |enrollment_id, challenge| {
            captured_for_second
                .lock()
                .map_err(|_| anyhow!("profile capture lock poisoned"))?
                .push((enrollment_id.to_owned(), challenge.to_owned()));
            Ok(b"ade-profile-v2".to_vec())
        },
    )?;
    assert_eq!(second_profile, b"ade-profile-v2".to_vec());
    assert_eq!(captured.lock().unwrap().len(), 2);
    assert_eq!(store.enrollments(None)?.len(), 3);
    Ok(())
}

#[test]
fn stale_kiosk_is_failed_before_dispatch_and_read_only_queue_progresses() -> Result<()> {
    let store = Store::memory()?;
    let udid = "00000000-0000-0000-0000-000000000112";
    let enrollment = active_enrollment(
        &store,
        "operations-kiosk-expiry-cert",
        udid,
        "OPS-SERIAL-112",
        "18.0",
        BASE_TIME,
    )?;

    let info_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "kiosk-expiry-info",
        BASE_TIME + 4,
    )?;
    let info_wire = dispatch(&store, "operations-kiosk-expiry-cert", udid, BASE_TIME + 5)?;
    assert_eq!(request_type(&info_wire)?, "DeviceInformation");
    acknowledge(
        &store,
        "operations-kiosk-expiry-cert",
        udid,
        &info_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><true/></dict>"#,
        BASE_TIME + 6,
    )?;

    let installed_id = store.enqueue(
        &enrollment,
        &CommandPayload::InstalledApplicationList {
            identifiers: Some(vec!["com.example.kiosk".into()]),
            managed_apps_only: false,
            items: None,
        },
        "kiosk-expiry-installed",
        BASE_TIME + 7,
    )?;
    let installed_wire = dispatch(&store, "operations-kiosk-expiry-cert", udid, BASE_TIME + 8)?;
    assert_eq!(request_type(&installed_wire)?, "InstalledApplicationList");
    acknowledge(
        &store,
        "operations-kiosk-expiry-cert",
        udid,
        &installed_id,
        r#"<key>InstalledApplicationList</key><array><dict><key>Identifier</key><string>com.example.kiosk</string><key>Installing</key><false/></dict></array>"#,
        BASE_TIME + 9,
    )?;

    let kiosk_id = store.apply_kiosk(
        &enrollment,
        "com.example.kiosk",
        "kiosk-expiry-apply",
        BASE_TIME + 10,
    )?;
    let query_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["DeviceName".into()],
        },
        "kiosk-expiry-next-query",
        BASE_TIME + 11,
    )?;

    // The kiosk evidence is older than the one-day freshness window. The
    // failed mutation must be consumed locally so it is never sent to the
    // device, and the following read-only command must still make progress.
    let expired_at = BASE_TIME + 86400 + 10;
    assert!(
        store
            .poll(
                "operations-kiosk-expiry-cert",
                &idle_response(udid)?,
                expired_at,
            )?
            .is_none()
    );
    let failed = store.command(&kiosk_id)?;
    assert_eq!(failed.state, "failed");
    assert_eq!(
        failed.result,
        Some(json!({"local_error": "operation_prerequisites_changed"}))
    );
    assert_eq!(failed.notification_state, "cancelled");

    let query_wire = dispatch(&store, "operations-kiosk-expiry-cert", udid, expired_at + 1)?;
    assert_eq!(request_type(&query_wire)?, "DeviceInformation");
    acknowledge(
        &store,
        "operations-kiosk-expiry-cert",
        udid,
        &query_id,
        r#"<key>QueryResponses</key><dict><key>DeviceName</key><string>Fresh Query</string></dict>"#,
        expired_at + 2,
    )?;
    assert_eq!(store.command(&query_id)?.state, "completed");
    Ok(())
}

#[test]
fn same_epoch_device_information_response_uses_dispatch_order() -> Result<()> {
    let store = Store::memory()?;
    let udid = "00000000-0000-0000-0000-000000000113";
    let enrollment = active_enrollment(
        &store,
        "operations-observation-order-cert",
        udid,
        "OPS-SERIAL-113",
        "18.0",
        BASE_TIME,
    )?;
    let first_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "observation-order-first",
        BASE_TIME + 4,
    )?;
    let second_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "observation-order-second",
        BASE_TIME + 4,
    )?;

    let first_wire = dispatch(
        &store,
        "operations-observation-order-cert",
        udid,
        BASE_TIME + 5,
    )?;
    assert_eq!(request_type(&first_wire)?, "DeviceInformation");
    // Use the same poll timestamp for the first response and the next
    // dispatch. Timestamp-only ordering would treat the second observation as
    // stale even though it belongs to the newer delivery attempt.
    let second_wire = store
        .poll(
            "operations-observation-order-cert",
            &acknowledged_response(
                udid,
                &first_id,
                r#"<key>QueryResponses</key><dict><key>IsSupervised</key><true/></dict>"#,
            )?,
            BASE_TIME + 5,
        )?
        .context("second device information command was not dispatched")?;
    assert_eq!(request_type(&second_wire)?, "DeviceInformation");
    assert_eq!(store.command(&first_id)?.state, "completed");
    assert_eq!(store.command(&second_id)?.attempt_count, 1);

    acknowledge(
        &store,
        "operations-observation-order-cert",
        udid,
        &second_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><false/></dict>"#,
        BASE_TIME + 6,
    )?;
    let observation = store
        .observations(&enrollment)?
        .into_iter()
        .find(|observation| observation.category == "device_information")
        .context("device information observation missing")?;
    assert_eq!(observation.command_id, second_id);
    assert_eq!(observation.body["QueryResponses"]["IsSupervised"], false);
    Ok(())
}

#[test]
fn device_configured_requires_awaiting_supervised_and_clears_flag() -> Result<()> {
    let store = Store::memory()?;
    let udid = "00000000-0000-0000-0000-000000000114";
    let fingerprint = "operations-device-configured-cert";
    let enrollment = active_enrollment(
        &store,
        fingerprint,
        udid,
        "OPS-SERIAL-114",
        "18.0",
        BASE_TIME,
    )?;
    store.checkin(
        fingerprint,
        &CheckIn::TokenUpdate {
            udid: udid.into(),
            topic: TOPIC.into(),
            token: vec![1, 2, 3, 4],
            push_magic: "push-magic-device-configured".into(),
            unlock_token: None,
            awaiting_configuration: true,
        },
        BASE_TIME + 4,
    )?;
    assert!(
        store
            .enrollments(None)?
            .into_iter()
            .find(|view| view.id == enrollment)
            .context("device configured enrollment disappeared")?
            .awaiting_configuration
    );

    // DeviceConfigured is gated by fresh supervised evidence, which is
    // collected while the enrollment is still awaiting configuration.
    let info_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceInformation {
            queries: vec!["IsSupervised".into()],
        },
        "device-configured-info",
        BASE_TIME + 5,
    )?;
    dispatch(&store, fingerprint, udid, BASE_TIME + 6)?;
    acknowledge(
        &store,
        fingerprint,
        udid,
        &info_id,
        r#"<key>QueryResponses</key><dict><key>IsSupervised</key><true/></dict>"#,
        BASE_TIME + 7,
    )?;

    let configured_id = store.enqueue(
        &enrollment,
        &CommandPayload::DeviceConfigured,
        "device-configured-release",
        BASE_TIME + 8,
    )?;
    let configured_wire = dispatch(&store, fingerprint, udid, BASE_TIME + 9)?;
    assert_eq!(request_type(&configured_wire)?, "DeviceConfigured");
    acknowledge(
        &store,
        fingerprint,
        udid,
        &configured_id,
        "",
        BASE_TIME + 10,
    )?;
    assert_eq!(store.command(&configured_id)?.state, "completed");
    assert!(
        !store
            .enrollments(None)?
            .into_iter()
            .find(|view| view.id == enrollment)
            .context("device configured enrollment disappeared after ACK")?
            .awaiting_configuration
    );
    assert!(
        store
            .enqueue(
                &enrollment,
                &CommandPayload::DeviceConfigured,
                "device-configured-repeat",
                BASE_TIME + 11,
            )
            .is_err()
    );
    Ok(())
}
