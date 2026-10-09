use anyhow::{Result, anyhow};
use mdm_protocol::{CheckIn, CommandPayload, DeviceResponse, parse_checkin, parse_response};
use mdmd::storage::{IssuedCertificate, RESPONSE_TIMEOUT_SECONDS, Store};
use std::fs;
use tempfile::tempdir;

const BASE_TIME: i64 = 1_800_000_000;
const UDID: &str = "00000000-0000-0000-0000-000000000001";
const TOPIC: &str = "com.apple.mgmt.test";

fn authenticate_xml(udid: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MessageType</key><string>Authenticate</string>
<key>UDID</key><string>{udid}</string>
<key>Topic</key><string>{TOPIC}</string>
<key>SerialNumber</key><string>SYNTHETIC-001</string>
<key>OSVersion</key><string>18.0</string>
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

fn response_xml(udid: &str, command_uuid: Option<&str>, status: &str) -> Vec<u8> {
    let command = command_uuid
        .map(|uuid| format!("<key>CommandUUID</key><string>{uuid}</string>"))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>{status}</string>
{command}
</dict></plist>"#
    )
    .into_bytes()
}

fn response_xml_reordered(udid: &str, command_uuid: &str, status: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CommandUUID</key><string>{command_uuid}</string>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>{status}</string>
</dict></plist>"#
    )
    .into_bytes()
}

fn response_xml_with_detail(udid: &str, command_uuid: &str, status: &str, detail: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UDID</key><string>{udid}</string>
<key>Status</key><string>{status}</string>
<key>CommandUUID</key><string>{command_uuid}</string>
<key>Detail</key><string>{detail}</string>
</dict></plist>"#
    )
    .into_bytes()
}

fn parsed_response(udid: &str, command_uuid: Option<&str>, status: &str) -> Result<DeviceResponse> {
    Ok(parse_response(&response_xml(udid, command_uuid, status))?)
}

fn idle_response(udid: &str) -> Result<DeviceResponse> {
    parsed_response(udid, None, "Idle")
}

fn active_enrollment(store: &Store, fingerprint: &str, udid: &str, time: i64) -> Result<String> {
    let challenge = format!("challenge-{fingerprint}");
    let request_hash = format!("request-{fingerprint}");
    let enrollment_id = store.create_enrollment(&challenge, time)?;
    let response = store.issue_identity(&challenge, &request_hash, time + 1, |_id| {
        Ok(IssuedCertificate {
            fingerprint: fingerprint.to_owned(),
            expires_at: "2035-01-01T00:00:00Z".to_owned(),
            response: format!("cert-reply-{fingerprint}").into_bytes(),
        })
    })?;
    assert_eq!(response, format!("cert-reply-{fingerprint}").into_bytes());

    let authenticate = parse_checkin(&authenticate_xml(udid))?;
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
    assert!(enrollment.push_ready);
    Ok(enrollment_id)
}

fn device_information() -> CommandPayload {
    CommandPayload::DeviceInformation {
        queries: vec!["UDID".to_owned(), "OSVersion".to_owned()],
    }
}

fn remove_profile() -> CommandPayload {
    CommandPayload::RemoveProfile {
        identifier: "com.example.profile".to_owned(),
    }
}

fn install_profile() -> CommandPayload {
    CommandPayload::InstallProfile {
        payload: br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>PayloadContent</key><array/>
<key>PayloadIdentifier</key><string>com.example.profile</string>
<key>PayloadOrganization</key><string>Example Organization</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>00000000-0000-0000-0000-000000000002</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"#
            .to_vec(),
    }
}

fn command_state(store: &Store, id: &str) -> Result<String> {
    Ok(store.command(id)?.state)
}

#[test]
fn restart_reclaims_an_expired_notification_lease_without_losing_the_command() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("mdm.sqlite");
    let store = Store::open(&database)?;
    let enrollment_id = active_enrollment(&store, "cert-restart", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "restart-key",
        BASE_TIME + 4,
    )?;

    let first_job = store
        .claim_notification(BASE_TIME + 4)?
        .ok_or_else(|| anyhow!("first notification was not claimable"))?;
    assert_eq!(first_job.attempt, 1);
    assert_eq!(command_state(&store, &command_id)?, "queued");
    drop(store);

    let reopened = Store::open(&database)?;
    let second_job = reopened
        .claim_notification(BASE_TIME + 65)?
        .ok_or_else(|| anyhow!("expired notification lease was not reclaimed"))?;
    assert_eq!(second_job.id, first_job.id);
    assert_eq!(second_job.attempt, 2);

    // A stale worker cannot overwrite the reclaimed lease.
    reopened.finish_notification(
        &first_job,
        "rejected",
        Some("stale-worker"),
        Some("stale-apns-id"),
        BASE_TIME + 65,
    )?;
    assert_eq!(reopened.command(&command_id)?.notification_state, "leased");

    reopened.finish_notification(
        &second_job,
        "accepted",
        None,
        Some("apns-id-2"),
        BASE_TIME + 66,
    )?;
    let view = reopened.command(&command_id)?;
    assert_eq!(view.state, "queued");
    assert_eq!(view.notification_state, "accepted");
    assert_eq!(view.notification_attempts, 2);
    Ok(())
}

#[test]
fn enqueue_idempotency_returns_the_same_command_and_rejects_a_key_mismatch() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-idempotency", UDID, BASE_TIME)?;

    let first = store.enqueue(
        &enrollment_id,
        &device_information(),
        "same-key",
        BASE_TIME + 4,
    )?;
    let replay = store.enqueue(
        &enrollment_id,
        &device_information(),
        "same-key",
        BASE_TIME + 5,
    )?;
    assert_eq!(replay, first);

    let conflict = store.enqueue(&enrollment_id, &remove_profile(), "same-key", BASE_TIME + 6);
    assert!(conflict.is_err());
    assert_eq!(store.command(&first)?.attempt_count, 0);
    Ok(())
}

#[test]
fn failed_certificate_issuance_rolls_back_and_allows_a_retry() -> Result<()> {
    let store = Store::memory()?;
    let challenge = "atomic-issue-challenge";
    let request_hash = "atomic-issue-request";
    let enrollment_id = store.create_enrollment(challenge, BASE_TIME)?;

    let failed = store.issue_identity(challenge, request_hash, BASE_TIME + 1, |_id| {
        Err(anyhow!("synthetic issuer failure"))
    });
    assert!(failed.is_err());
    let pending = store
        .enrollments(None)?
        .into_iter()
        .find(|view| view.id == enrollment_id)
        .ok_or_else(|| anyhow!("enrollment disappeared after rollback"))?;
    assert_eq!(pending.state, "pending");
    assert!(pending.certificate_expires_at.is_none());

    let issued = store.issue_identity(challenge, request_hash, BASE_TIME + 2, |_id| {
        Ok(IssuedCertificate {
            fingerprint: "cert-atomic".to_owned(),
            expires_at: "2035-01-01T00:00:00Z".to_owned(),
            response: b"successful-cert-reply".to_vec(),
        })
    })?;
    assert_eq!(issued, b"successful-cert-reply".to_vec());

    let replay = store.issue_identity(challenge, request_hash, BASE_TIME + 3, |_id| {
        Err(anyhow!("replay must use persisted response"))
    })?;
    assert_eq!(replay, issued);
    Ok(())
}

#[test]
fn malformed_response_status_does_not_mutate_an_awaiting_command() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-malformed", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &remove_profile(),
        "malformed-response-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    assert!(
        store
            .poll("cert-malformed", &idle, BASE_TIME + 5)?
            .is_some()
    );
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    let malformed = parse_response(&response_xml(UDID, Some(&command_id), "UnexpectedStatus"));
    assert!(malformed.is_err());
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll("cert-malformed", &acknowledged, BASE_TIME + 6)?
            .is_none()
    );
    assert_eq!(command_state(&store, &command_id)?, "completed");
    Ok(())
}

#[test]
fn accepted_notification_keeps_command_queued_until_device_poll_acknowledges() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-notification", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "notification-key",
        BASE_TIME + 4,
    )?;
    let job = store
        .claim_notification(BASE_TIME + 4)?
        .ok_or_else(|| anyhow!("notification was not claimable"))?;
    store.finish_notification(&job, "accepted", None, Some("apns-accepted"), BASE_TIME + 5)?;
    let view = store.command(&command_id)?;
    assert_eq!(view.state, "queued");
    assert_eq!(view.notification_state, "accepted");

    let idle = idle_response(UDID)?;
    assert!(
        store
            .poll("cert-notification", &idle, BASE_TIME + 6)?
            .is_some()
    );
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll("cert-notification", &acknowledged, BASE_TIME + 7)?
            .is_none()
    );
    let view = store.command(&command_id)?;
    assert_eq!(view.state, "completed");
    assert_eq!(view.notification_state, "accepted");
    Ok(())
}

#[test]
fn notification_retry_and_rejection_are_recorded_without_dispatching_the_command() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-notification-retry", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "notification-retry-key",
        BASE_TIME + 4,
    )?;
    let first_job = store
        .claim_notification(BASE_TIME + 4)?
        .ok_or_else(|| anyhow!("notification was not claimable"))?;
    store.finish_notification(
        &first_job,
        "retry",
        Some("temporary APNs failure"),
        None,
        BASE_TIME + 5,
    )?;
    let pending = store.command(&command_id)?;
    assert_eq!(pending.notification_state, "pending");
    assert_eq!(
        pending.notification_reason.as_deref(),
        Some("temporary APNs failure")
    );

    let second_job = store
        .claim_notification(BASE_TIME + 15)?
        .ok_or_else(|| anyhow!("retry notification was not available"))?;
    store.finish_notification(
        &second_job,
        "rejected",
        Some("BadDeviceToken"),
        Some("apns-rejected"),
        BASE_TIME + 16,
    )?;
    let rejected = store.command(&command_id)?;
    assert_eq!(rejected.state, "queued");
    assert_eq!(rejected.notification_state, "rejected");
    assert_eq!(
        rejected.notification_reason.as_deref(),
        Some("BadDeviceToken")
    );
    Ok(())
}

#[test]
fn wrong_certificate_udid_and_unsolicited_uuid_are_rejected_without_state_change() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-identity", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "identity-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    assert!(store.poll("cert-identity", &idle, BASE_TIME + 5)?.is_some());

    assert!(
        store
            .poll("wrong-certificate", &idle, BASE_TIME + 6)
            .is_err()
    );
    let wrong_udid = parsed_response("wrong-udid", Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll("cert-identity", &wrong_udid, BASE_TIME + 7)
            .is_err()
    );
    let guessed_uuid = parsed_response(
        UDID,
        Some("00000000-0000-0000-0000-000000000099"),
        "Acknowledged",
    )?;
    assert!(
        store
            .poll("cert-identity", &guessed_uuid, BASE_TIME + 8)
            .is_err()
    );
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    store.poll("cert-identity", &acknowledged, BASE_TIME + 9)?;
    assert_eq!(command_state(&store, &command_id)?, "completed");
    Ok(())
}

#[test]
fn duplicate_terminal_response_is_idempotent_only_when_its_body_matches() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-terminal-duplicate", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "terminal-duplicate-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    store.poll("cert-terminal-duplicate", &idle, BASE_TIME + 5)?;

    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    store.poll("cert-terminal-duplicate", &acknowledged, BASE_TIME + 6)?;
    assert_eq!(command_state(&store, &command_id)?, "completed");

    // Plist dictionary order has no semantics. A retransmission with the same
    // fields in a different order must use the same canonical response body.
    let reordered = parse_response(&response_xml_reordered(UDID, &command_id, "Acknowledged"))?;
    assert!(
        store
            .poll("cert-terminal-duplicate", &reordered, BASE_TIME + 7)?
            .is_none()
    );
    assert_eq!(command_state(&store, &command_id)?, "completed");

    // The same raw response is an idempotent replay.
    assert!(
        store
            .poll("cert-terminal-duplicate", &acknowledged, BASE_TIME + 8)?
            .is_none()
    );
    assert_eq!(command_state(&store, &command_id)?, "completed");

    // A same-status response with a different body is a conflict, not a new result.
    let conflicting = parse_response(&response_xml_with_detail(
        UDID,
        &command_id,
        "Acknowledged",
        "different-body",
    ))?;
    assert!(
        store
            .poll("cert-terminal-duplicate", &conflicting, BASE_TIME + 9)
            .is_err()
    );
    assert_eq!(command_state(&store, &command_id)?, "completed");
    Ok(())
}

#[test]
fn reenrollment_revokes_the_old_generation_and_checkout_cannot_resurrect_it() -> Result<()> {
    let store = Store::memory()?;
    let old_id = active_enrollment(&store, "cert-old-generation", UDID, BASE_TIME)?;
    let old_command = store.enqueue(
        &old_id,
        &device_information(),
        "old-generation-command",
        BASE_TIME + 4,
    )?;

    let new_id = active_enrollment(&store, "cert-new-generation", UDID, BASE_TIME + 10)?;
    assert_ne!(old_id, new_id);
    assert_eq!(command_state(&store, &old_command)?, "cancelled");

    let idle = idle_response(UDID)?;
    assert!(
        store
            .poll("cert-old-generation", &idle, BASE_TIME + 14)
            .is_err()
    );
    let old_checkout = CheckIn::CheckOut {
        udid: UDID.to_owned(),
    };
    assert!(
        store
            .checkin("cert-old-generation", &old_checkout, BASE_TIME + 15)
            .is_err()
    );

    let new_command = store.enqueue(
        &new_id,
        &device_information(),
        "new-generation-command",
        BASE_TIME + 16,
    )?;
    let new_checkout = CheckIn::CheckOut {
        udid: UDID.to_owned(),
    };
    store.checkin("cert-new-generation", &new_checkout, BASE_TIME + 17)?;
    assert_eq!(command_state(&store, &new_command)?, "cancelled");
    assert!(
        store
            .poll("cert-new-generation", &idle, BASE_TIME + 18)
            .is_err()
    );

    let token_update = parse_checkin(&token_update_xml(UDID))?;
    assert!(
        store
            .checkin("cert-new-generation", &token_update, BASE_TIME + 19)
            .is_err()
    );
    Ok(())
}

#[test]
fn not_now_defers_and_a_late_terminal_response_resolves_the_same_command() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-not-now", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &remove_profile(),
        "not-now-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    assert!(store.poll("cert-not-now", &idle, BASE_TIME + 5)?.is_some());

    let not_now = parsed_response(UDID, Some(&command_id), "NotNow")?;
    assert!(
        store
            .poll("cert-not-now", &not_now, BASE_TIME + 6)?
            .is_none()
    );
    let deferred = store.command(&command_id)?;
    assert_eq!(deferred.state, "deferred");
    assert_eq!(deferred.notification_state, "pending");

    // Repeating the exact response is idempotent and does not create another retry.
    assert!(
        store
            .poll("cert-not-now", &not_now, BASE_TIME + 7)?
            .is_none()
    );
    assert_eq!(store.command(&command_id)?.state, "deferred");

    // A terminal response from the earlier attempt can still arrive before retry.
    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll("cert-not-now", &acknowledged, BASE_TIME + 8)?
            .is_none()
    );
    let completed = store.command(&command_id)?;
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.notification_state, "cancelled");
    Ok(())
}

#[test]
fn mutation_timeout_becomes_unknown_until_manual_cancellation() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-mutation-timeout", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &install_profile(),
        "mutation-timeout-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    store.poll("cert-mutation-timeout", &idle, BASE_TIME + 5)?;
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    assert_eq!(
        store.recover_timeouts(BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 6)?,
        1
    );
    assert_eq!(command_state(&store, &command_id)?, "outcome_unknown");
    assert!(
        store
            .poll(
                "cert-mutation-timeout",
                &idle_response(UDID)?,
                BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 7,
            )?
            .is_none()
    );

    store.cancel_command(&command_id, BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 8)?;
    assert_eq!(command_state(&store, &command_id)?, "cancelled");
    let late_ack = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll(
                "cert-mutation-timeout",
                &late_ack,
                BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 9,
            )?
            .is_none()
    );
    assert_eq!(command_state(&store, &command_id)?, "cancelled");
    Ok(())
}

#[test]
fn cancelled_dispatched_command_ignores_late_response_and_dispatches_next_command() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-cancelled-late", UDID, BASE_TIME)?;
    let cancelled_id = store.enqueue(
        &enrollment_id,
        &remove_profile(),
        "cancelled-late-key",
        BASE_TIME + 4,
    )?;
    store.poll("cert-cancelled-late", &idle_response(UDID)?, BASE_TIME + 5)?;
    store.cancel_command(&cancelled_id, BASE_TIME + 6)?;
    assert_eq!(command_state(&store, &cancelled_id)?, "cancelled");

    let next_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "cancelled-late-next-key",
        BASE_TIME + 7,
    )?;
    let late_ack = parsed_response(UDID, Some(&cancelled_id), "Acknowledged")?;
    let next = store
        .poll("cert-cancelled-late", &late_ack, BASE_TIME + 8)?
        .ok_or_else(|| anyhow!("next command was not returned after late response"))?;
    assert!(
        next.windows(next_id.len())
            .any(|window| window == next_id.as_bytes())
    );
    assert_eq!(command_state(&store, &cancelled_id)?, "cancelled");
    assert_eq!(command_state(&store, &next_id)?, "awaiting_response");

    // A queued command that was never dispatched still rejects an unsolicited
    // response because attempt_count remains zero.
    let never_dispatched = store.enqueue(
        &enrollment_id,
        &remove_profile(),
        "cancelled-never-dispatched-key",
        BASE_TIME + 9,
    )?;
    store.cancel_command(&never_dispatched, BASE_TIME + 10)?;
    let unsolicited = parsed_response(UDID, Some(&never_dispatched), "Acknowledged")?;
    assert!(
        store
            .poll("cert-cancelled-late", &unsolicited, BASE_TIME + 11)
            .is_err()
    );

    let audits = store.audits(0)?;
    assert!(audits.iter().any(|entry| {
        entry.get("action").and_then(serde_json::Value::as_str)
            == Some("late_cancelled_response_ignored")
            && entry.get("resource_id").and_then(serde_json::Value::as_str)
                == Some(cancelled_id.as_str())
    }));
    Ok(())
}

#[test]
fn device_information_timeout_requeues_the_same_uuid_for_a_safe_retry() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-device-info-timeout", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "device-info-timeout-key",
        BASE_TIME + 4,
    )?;
    let idle = idle_response(UDID)?;
    let first_bytes = store
        .poll("cert-device-info-timeout", &idle, BASE_TIME + 5)?
        .ok_or_else(|| anyhow!("first device information dispatch missing"))?;
    assert!(
        first_bytes
            .windows(command_id.len())
            .any(|window| window == command_id.as_bytes())
    );
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    assert_eq!(
        store.recover_timeouts(BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 6)?,
        1
    );
    assert_eq!(command_state(&store, &command_id)?, "queued");

    let second_bytes = store
        .poll(
            "cert-device-info-timeout",
            &idle_response(UDID)?,
            BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 7,
        )?
        .ok_or_else(|| anyhow!("safe retry was not dispatched"))?;
    assert!(
        second_bytes
            .windows(command_id.len())
            .any(|window| window == command_id.as_bytes())
    );
    assert_eq!(store.command(&command_id)?.attempt_count, 2);

    let acknowledged = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    store.poll(
        "cert-device-info-timeout",
        &acknowledged,
        BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 8,
    )?;
    assert_eq!(command_state(&store, &command_id)?, "completed");
    Ok(())
}

#[test]
fn device_information_timeout_accepts_a_late_ack_while_still_queued() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-device-info-late", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "device-info-late-key",
        BASE_TIME + 4,
    )?;
    store.poll(
        "cert-device-info-late",
        &idle_response(UDID)?,
        BASE_TIME + 5,
    )?;
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");

    assert_eq!(
        store.recover_timeouts(BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 6)?,
        1
    );
    assert_eq!(command_state(&store, &command_id)?, "queued");

    // The read-only command timed out, but its original answer can arrive
    // before the safe retry is dispatched.
    let late_ack = parsed_response(UDID, Some(&command_id), "Acknowledged")?;
    assert!(
        store
            .poll(
                "cert-device-info-late",
                &late_ack,
                BASE_TIME + RESPONSE_TIMEOUT_SECONDS + 7,
            )?
            .is_none()
    );
    let view = store.command(&command_id)?;
    assert_eq!(view.state, "completed");
    assert_eq!(view.attempt_count, 1);
    Ok(())
}

#[test]
fn backup_reopens_as_a_consistent_snapshot() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("mdm.sqlite");
    let backup = directory.path().join("mdm-backup.sqlite");
    let store = Store::open(&database)?;
    let enrollment_id = active_enrollment(&store, "cert-backup", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "backup-key",
        BASE_TIME + 4,
    )?;
    store.backup(&backup)?;

    let restored = Store::open(&backup)?;
    let view = restored.command(&command_id)?;
    assert_eq!(view.enrollment_id, enrollment_id);
    assert_eq!(view.state, "queued");
    assert_eq!(restored.enrollments(None)?.len(), 1);
    Ok(())
}

#[test]
fn accepted_notification_is_requeued_after_300_seconds_without_a_device_poll() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-apns-repush", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "apns-repush-key",
        BASE_TIME + 4,
    )?;
    let first_job = store
        .claim_notification(BASE_TIME + 4)?
        .ok_or_else(|| anyhow!("initial APNs notification was not claimable"))?;
    store.finish_notification(
        &first_job,
        "accepted",
        None,
        Some("apns-first"),
        BASE_TIME + 5,
    )?;
    assert_eq!(store.command(&command_id)?.notification_state, "accepted");

    assert!(store.claim_notification(BASE_TIME + 304)?.is_none());
    let repush = store
        .claim_notification(BASE_TIME + 305)?
        .ok_or_else(|| anyhow!("accepted notification was not requeued at 300 seconds"))?;
    assert_eq!(repush.id, first_job.id);
    assert_eq!(repush.attempt, 2);

    store.finish_notification(
        &repush,
        "rejected",
        Some("BadDeviceToken"),
        Some("apns-second"),
        BASE_TIME + 306,
    )?;
    let view = store.command(&command_id)?;
    assert_eq!(view.state, "queued");
    assert_eq!(view.notification_state, "rejected");
    assert_eq!(view.notification_reason.as_deref(), Some("BadDeviceToken"));
    Ok(())
}

#[test]
fn an_expired_scep_challenge_cannot_issue_an_identity() -> Result<()> {
    let store = Store::memory()?;
    let challenge = "expired-scep-challenge";
    store.create_enrollment(challenge, BASE_TIME)?;

    let result = store.issue_identity(challenge, "expired-request", BASE_TIME + 900, |_id| {
        Ok(IssuedCertificate {
            fingerprint: "cert-expired".to_owned(),
            expires_at: "2035-01-01T00:00:00Z".to_owned(),
            response: b"must-not-be-issued".to_vec(),
        })
    });
    assert!(result.is_err());
    assert!(
        store
            .enrollments(None)?
            .into_iter()
            .all(|enrollment| enrollment.certificate_expires_at.is_none())
    );
    Ok(())
}

#[test]
fn scep_replay_after_expiry_is_exactly_idempotent_but_mismatch_and_revoke_are_rejected()
-> Result<()> {
    let store = Store::memory()?;
    let challenge = "replay-scep-challenge";
    let request_hash = "replay-scep-request";
    let enrollment_id = store.create_enrollment(challenge, BASE_TIME)?;
    let issued = store.issue_identity(challenge, request_hash, BASE_TIME + 1, |_id| {
        Ok(IssuedCertificate {
            fingerprint: "cert-scep-replay".to_owned(),
            expires_at: "2035-01-01T00:00:00Z".to_owned(),
            response: b"stored-cert-reply".to_vec(),
        })
    })?;

    let replay_after_expiry =
        store.issue_identity(challenge, request_hash, BASE_TIME + 901, |_id| {
            Err(anyhow!("exact replay must use the stored response"))
        })?;
    assert_eq!(replay_after_expiry, issued);

    let mismatch = store.issue_identity(challenge, "different-request", BASE_TIME + 902, |_id| {
        Err(anyhow!("mismatched replay must not invoke issuer"))
    });
    assert!(mismatch.is_err());

    store.revoke(&enrollment_id, BASE_TIME + 903)?;
    let revoked_replay = store.issue_identity(challenge, request_hash, BASE_TIME + 904, |_id| {
        Err(anyhow!("revoked replay must not invoke issuer"))
    });
    assert!(revoked_replay.is_err());
    Ok(())
}

#[test]
fn backup_rejects_an_existing_destination_and_writes_private_mode() -> Result<()> {
    let directory = tempdir()?;
    let database = directory.path().join("mdm.sqlite");
    let backup = directory.path().join("private-backup.sqlite");
    let existing = directory.path().join("existing.sqlite");
    let store = Store::open(&database)?;
    active_enrollment(&store, "cert-backup-permissions", UDID, BASE_TIME)?;

    fs::write(&existing, b"")?;
    assert!(store.backup(&existing).is_err());
    assert_eq!(fs::metadata(&existing)?.len(), 0);

    store.backup(&backup)?;
    assert!(fs::metadata(&backup)?.len() > 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&backup)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

#[test]
fn conflicting_response_rolls_back_without_changing_queued_state_or_audit_history() -> Result<()> {
    let store = Store::memory()?;
    let enrollment_id = active_enrollment(&store, "cert-response-conflict", UDID, BASE_TIME)?;
    let command_id = store.enqueue(
        &enrollment_id,
        &device_information(),
        "response-conflict-key",
        BASE_TIME + 4,
    )?;
    let audits_before = store.audits(0)?;
    let unsolicited = parsed_response(UDID, Some(&command_id), "Acknowledged")?;

    assert!(
        store
            .poll("cert-response-conflict", &unsolicited, BASE_TIME + 5)
            .is_err()
    );
    assert_eq!(command_state(&store, &command_id)?, "queued");
    assert_eq!(store.audits(0)?, audits_before);

    // The rollback left the outbox usable for the legitimate first dispatch.
    assert!(
        store
            .poll(
                "cert-response-conflict",
                &idle_response(UDID)?,
                BASE_TIME + 6,
            )?
            .is_some()
    );
    assert_eq!(command_state(&store, &command_id)?, "awaiting_response");
    Ok(())
}
