use mdm_protocol::{
    ApplicationInstallSource, CheckIn, CommandPayload, DeclarationKind, DeclarativeEndpoint,
    DeviceResponse, EnrollmentProfile, ObliterationBehavior, OsInstallAction, OsUpdate,
    OsUpdatePriority, ResponseStatus, encode_command, enrollment_profile, kiosk_profile,
    parse_checkin, parse_declaration_items_response, parse_response, parse_status_report,
    parse_tokens_response,
};
use plist::Value;

const UDID: &str = "00000000-0000-0000-0000-000000000001";

#[test]
fn parses_authenticate_fixture() {
    let parsed = parse_checkin(include_bytes!("fixtures/authenticate.plist")).unwrap();
    match parsed {
        CheckIn::Authenticate {
            udid,
            topic,
            serial_number,
            os_version,
        } => {
            assert_eq!(udid, UDID);
            assert_eq!(topic, "com.apple.mgmt.test");
            assert_eq!(serial_number.as_deref(), Some("SYNTHETIC-001"));
            assert_eq!(os_version.as_deref(), Some("18.0"));
        }
        _ => panic!("expected Authenticate"),
    }
}

#[test]
fn parses_token_update_fixture_and_defaults_are_explicit() {
    let parsed = parse_checkin(include_bytes!("fixtures/token-update.plist")).unwrap();
    match parsed {
        CheckIn::TokenUpdate {
            udid,
            topic,
            token,
            push_magic,
            unlock_token,
            awaiting_configuration,
        } => {
            assert_eq!(udid, UDID);
            assert_eq!(topic, "com.apple.mgmt.test");
            assert_eq!(token, vec![1, 2, 3, 4]);
            assert_eq!(push_magic, "push-magic");
            assert_eq!(unlock_token, Some(b"encrypted".to_vec()));
            assert!(awaiting_configuration);
        }
        _ => panic!("expected TokenUpdate"),
    }
}

#[test]
fn parses_checkout_fixture() {
    assert!(matches!(
        parse_checkin(include_bytes!("fixtures/checkout.plist")).unwrap(),
        CheckIn::CheckOut { udid } if udid == UDID
    ));
}

#[test]
fn parses_declarative_management_tokens_fixture() {
    let parsed = parse_checkin(include_bytes!("fixtures/declarative-tokens.plist")).unwrap();
    match parsed {
        CheckIn::DeclarativeManagement {
            udid,
            endpoint,
            data,
        } => {
            assert_eq!(udid, UDID);
            assert_eq!(endpoint, DeclarativeEndpoint::Tokens);
            assert!(data.is_none());
        }
        _ => panic!("expected DeclarativeManagement"),
    }
}

#[test]
fn parses_declarative_management_status_json_from_plist_data() {
    let parsed = parse_checkin(include_bytes!("fixtures/declarative-status.plist")).unwrap();
    match parsed {
        CheckIn::DeclarativeManagement {
            udid,
            endpoint,
            data: Some(data),
        } => {
            assert_eq!(udid, UDID);
            assert_eq!(endpoint, DeclarativeEndpoint::Status);
            assert_eq!(data["FullReport"], true);
            assert_eq!(data["Errors"], serde_json::json!([]));
        }
        _ => panic!("expected status DeclarativeManagement"),
    }
}

#[test]
fn rejects_declarative_user_channel_and_endpoint_data_mismatch() {
    let user_channel = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>DeclarativeManagement</string>
        <key>Endpoint</key><string>tokens</string>
        <key>UDID</key><string>device</string>
        <key>EnrollmentID</key><string>user-enrollment</string>
    </dict></plist>"#;
    assert!(parse_checkin(user_channel).is_err());

    let data_on_tokens = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>DeclarativeManagement</string>
        <key>Endpoint</key><string>tokens</string>
        <key>UDID</key><string>device</string>
        <key>Data</key><data>e30=</data>
    </dict></plist>"#;
    assert!(parse_checkin(data_on_tokens).is_err());

    let missing_status_data = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>DeclarativeManagement</string>
        <key>Endpoint</key><string>status</string>
        <key>UDID</key><string>device</string>
    </dict></plist>"#;
    assert!(parse_checkin(missing_status_data).is_err());
}

#[test]
fn parses_and_validates_ddm_wire_responses() {
    let tokens = parse_tokens_response(
        br#"{"SyncTokens":{"DeclarationsToken":"revision-1","Timestamp":"2026-10-09T00:00:00Z"}}"#,
    )
    .unwrap();
    assert_eq!(tokens.sync_tokens.declarations_token, "revision-1");

    let declarations = parse_declaration_items_response(
        br#"{"Declarations":{"Activations":[{"Identifier":"activation-1","ServerToken":"token-a"}],"Configurations":[],"Assets":[],"Management":[]},"DeclarationsToken":"revision-1"}"#,
    )
    .unwrap();
    assert_eq!(declarations.declarations.activations.len(), 1);

    let report = parse_status_report(
        br#"{"StatusItems":{"device.identifier.udid":"device"},"Errors":[],"FullReport":false}"#,
    )
    .unwrap();
    assert!(!report.full_report);

    assert_eq!(
        DeclarativeEndpoint::Declaration {
            kind: DeclarationKind::Configuration,
            identifier: "configuration-1".into(),
        }
        .as_str(),
        "declaration/configuration/configuration-1"
    );
}

#[test]
fn encodes_declarative_management_activation_command() {
    let data = serde_json::json!({
        "SyncTokens": {
            "DeclarationsToken": "revision-1",
            "Timestamp": "2026-10-09T00:00:00Z"
        }
    });
    let encoded = encode_command(
        "command-ddm-001",
        &CommandPayload::DeclarativeManagement { data: Some(data) },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(encoded)).unwrap();
    let dict = root.as_dictionary().unwrap();
    assert_eq!(
        dict.get("CommandUUID").and_then(Value::as_string),
        Some("command-ddm-001")
    );
    let command = dict.get("Command").unwrap().as_dictionary().unwrap();
    assert_eq!(
        command.get("RequestType").and_then(Value::as_string),
        Some("DeclarativeManagement")
    );
    let bytes = command.get("Data").and_then(Value::as_data).unwrap();
    assert_eq!(
        parse_tokens_response(bytes)
            .unwrap()
            .sync_tokens
            .declarations_token,
        "revision-1"
    );
}

#[test]
fn rejects_declarative_command_data_without_sync_tokens() {
    let result = encode_command(
        "command-ddm-invalid",
        &CommandPayload::DeclarativeManagement {
            data: Some(serde_json::json!({"unexpected": true})),
        },
    );
    assert!(result.is_err());
}

#[test]
fn command_payload_json_names_match_management_api_literals() {
    let cases = [
        (CommandPayload::AvailableOSUpdates, "available_os_updates"),
        (CommandPayload::OSUpdateStatus, "os_update_status"),
        (
            CommandPayload::ScheduleOSUpdate {
                updates: vec![OsUpdate {
                    product_key: None,
                    product_version: Some("18.0".into()),
                    install_action: OsInstallAction::Default,
                    max_user_deferrals: None,
                    priority: None,
                }],
            },
            "schedule_os_update",
        ),
    ];
    for (command, expected_type) in cases {
        let encoded = serde_json::to_value(&command).unwrap();
        assert_eq!(encoded["type"], expected_type);
        assert_eq!(
            serde_json::from_value::<CommandPayload>(encoded).unwrap(),
            command
        );
    }

    for legacy_name in [
        "available_o_s_updates",
        "o_s_update_status",
        "schedule_o_s_update",
    ] {
        assert!(
            serde_json::from_value::<CommandPayload>(serde_json::json!({
                "type": legacy_name
            }))
            .is_err()
        );
    }
}

#[test]
fn rejects_bounds_and_unsupported_fields_for_new_commands() {
    assert!(
        CommandPayload::InstalledApplicationList {
            identifiers: Some(vec!["".into()]),
            managed_apps_only: false,
            items: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        CommandPayload::InstalledApplicationList {
            identifiers: None,
            managed_apps_only: false,
            items: Some(vec!["NotAnInstalledApplicationField".into()]),
        }
        .validate()
        .is_err()
    );
    assert!(
        CommandPayload::InstalledApplicationList {
            identifiers: Some(
                (0..=128)
                    .map(|index| format!("com.example.app{index}"))
                    .collect()
            ),
            managed_apps_only: false,
            items: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        CommandPayload::ScheduleOSUpdate { updates: vec![] }
            .validate()
            .is_err()
    );
    assert!(
        CommandPayload::ScheduleOSUpdate {
            updates: vec![OsUpdate {
                product_key: None,
                product_version: None,
                install_action: OsInstallAction::Default,
                max_user_deferrals: None,
                priority: None,
            }],
        }
        .validate()
        .is_err()
    );
    assert!(
        CommandPayload::DeviceLock {
            message: None,
            phone_number: None,
            pin: Some("123".into()),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn rejects_user_channel_and_unknown_checkins() {
    let user_channel = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>TokenUpdate</string>
        <key>UDID</key><string>device</string>
        <key>Topic</key><string>com.apple.mgmt.test</string>
        <key>Token</key><data>AQ==</data>
        <key>PushMagic</key><string>magic</string>
        <key>UserID</key><string>user</string>
    </dict></plist>"#;
    assert!(parse_checkin(user_channel).is_err());

    let unsupported = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>MessageType</key><string>GetToken</string>
    </dict></plist>"#;
    assert!(parse_checkin(unsupported).is_err());
}

#[test]
fn parses_response_and_preserves_raw_plist() {
    let response = parse_response(include_bytes!("fixtures/response.plist")).unwrap();
    assert_eq!(
        response,
        DeviceResponse {
            udid: UDID.into(),
            command_uuid: Some("command-001".into()),
            status: ResponseStatus::Acknowledged,
            raw: plist::from_bytes(include_bytes!("fixtures/response.plist")).unwrap(),
        }
    );
}

#[test]
fn requires_command_uuid_for_terminal_responses_and_rejects_it_for_idle() {
    let missing_uuid = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>UDID</key><string>device</string>
        <key>Status</key><string>Acknowledged</string>
    </dict></plist>"#;
    assert!(parse_response(missing_uuid).is_err());

    let idle_with_uuid = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>UDID</key><string>device</string>
        <key>Status</key><string>Idle</string>
        <key>CommandUUID</key><string>unexpected</string>
    </dict></plist>"#;
    assert!(parse_response(idle_with_uuid).is_err());
}

#[test]
fn encodes_device_information_command_with_known_queries() {
    let encoded = encode_command(
        "command-001",
        &CommandPayload::DeviceInformation {
            queries: vec!["UDID".into(), "OSVersion".into(), "SerialNumber".into()],
        },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(encoded)).unwrap();
    let dict = root.as_dictionary().unwrap();
    assert_eq!(
        dict.get("CommandUUID").and_then(Value::as_string),
        Some("command-001")
    );
    let command = dict.get("Command").unwrap().as_dictionary().unwrap();
    assert_eq!(
        command.get("RequestType").and_then(Value::as_string),
        Some("DeviceInformation")
    );
    assert_eq!(
        command
            .get("Queries")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn encodes_application_sources_with_device_license_or_https_manifest() {
    let app_store = encode_command(
        "command-app-store",
        &CommandPayload::InstallApplication {
            source: ApplicationInstallSource::AppStore {
                itunes_store_id: 1_096_834_193,
                purchase_method: 1,
            },
        },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(app_store)).unwrap();
    let command = root
        .as_dictionary()
        .unwrap()
        .get("Command")
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(
        command.get("RequestType").and_then(Value::as_string),
        Some("InstallApplication")
    );
    assert_eq!(
        command
            .get("iTunesStoreID")
            .and_then(Value::as_unsigned_integer),
        Some(1_096_834_193)
    );
    assert_eq!(
        command
            .get("Options")
            .and_then(Value::as_dictionary)
            .and_then(|options| options.get("PurchaseMethod"))
            .and_then(Value::as_unsigned_integer),
        Some(1)
    );

    let enterprise = encode_command(
        "command-enterprise",
        &CommandPayload::InstallApplication {
            source: ApplicationInstallSource::Enterprise {
                manifest_url: "https://mdm.example.test/apps/example.plist".into(),
            },
        },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(enterprise)).unwrap();
    let command = root
        .as_dictionary()
        .unwrap()
        .get("Command")
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(
        command.get("ManifestURL").and_then(Value::as_string),
        Some("https://mdm.example.test/apps/example.plist")
    );

    assert!(
        CommandPayload::InstallApplication {
            source: ApplicationInstallSource::AppStore {
                itunes_store_id: 1,
                purchase_method: 0,
            },
        }
        .validate()
        .is_err()
    );
    assert!(
        CommandPayload::InstallApplication {
            source: ApplicationInstallSource::Enterprise {
                manifest_url: "http://mdm.example.test/apps/example.plist".into(),
            },
        }
        .validate()
        .is_err()
    );
}

#[test]
fn encodes_application_inventory_lock_erase_and_ade_commands() {
    let installed = encode_command(
        "command-installed",
        &CommandPayload::InstalledApplicationList {
            identifiers: Some(vec!["com.example.app".into()]),
            managed_apps_only: true,
            items: Some(vec!["Identifier".into(), "Version".into()]),
        },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(installed)).unwrap();
    let command = root
        .as_dictionary()
        .unwrap()
        .get("Command")
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(
        command.get("RequestType").and_then(Value::as_string),
        Some("InstalledApplicationList")
    );
    assert_eq!(
        command.get("ManagedAppsOnly").and_then(Value::as_boolean),
        Some(true)
    );

    let scheduled = encode_command(
        "command-update",
        &CommandPayload::ScheduleOSUpdate {
            updates: vec![OsUpdate {
                product_key: None,
                product_version: Some("18.0".into()),
                install_action: OsInstallAction::DownloadOnly,
                max_user_deferrals: None,
                priority: Some(OsUpdatePriority::High),
            }],
        },
    )
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(scheduled)).unwrap();
    let command = root
        .as_dictionary()
        .unwrap()
        .get("Command")
        .unwrap()
        .as_dictionary()
        .unwrap();
    let update = command
        .get("Updates")
        .unwrap()
        .as_array()
        .unwrap()
        .first()
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(
        update.get("InstallAction").and_then(Value::as_string),
        Some("DownloadOnly")
    );
    assert_eq!(
        update.get("Priority").and_then(Value::as_string),
        Some("High")
    );

    let lock = CommandPayload::DeviceLock {
        message: Some("Return this device".into()),
        phone_number: Some("+81-000-0000".into()),
        pin: Some("123456".into()),
    };
    assert!(encode_command("command-lock", &lock).is_ok());
    let erase = CommandPayload::EraseDevice {
        preserve_data_plan: true,
        disallow_proximity_setup: false,
        pin: None,
        obliteration_behavior: Some(ObliterationBehavior::Default),
    };
    assert!(encode_command("command-erase", &erase).is_ok());
    assert!(encode_command("command-configured", &CommandPayload::DeviceConfigured).is_ok());
}

#[test]
fn builds_deterministic_supervised_app_lock_profile() {
    let first = kiosk_profile(
        "com.example.kiosk",
        "com.example.mdm.kiosk",
        "00000000-0000-0000-0000-000000000001",
    )
    .unwrap();
    let second = kiosk_profile(
        "com.example.kiosk",
        "com.example.mdm.kiosk",
        "00000000-0000-0000-0000-000000000001",
    )
    .unwrap();
    assert_eq!(first, second);
    let root = Value::from_reader(std::io::Cursor::new(first.clone())).unwrap();
    let profile = root.as_dictionary().unwrap();
    let payloads = profile.get("PayloadContent").unwrap().as_array().unwrap();
    let app_lock = payloads.first().unwrap().as_dictionary().unwrap();
    assert_eq!(
        app_lock.get("PayloadType").and_then(Value::as_string),
        Some("com.apple.app.lock")
    );
    assert_eq!(
        app_lock
            .get("App")
            .and_then(Value::as_dictionary)
            .and_then(|app| app.get("Identifier"))
            .and_then(Value::as_string),
        Some("com.example.kiosk")
    );
    assert!(
        encode_command(
            "command-kiosk",
            &CommandPayload::InstallProfile { payload: first },
        )
        .is_ok()
    );
}

#[test]
fn rejects_unknown_query_and_non_xml_profile() {
    let query_result = encode_command(
        "command-001",
        &CommandPayload::DeviceInformation {
            queries: vec!["NotAnAppleQuery".into()],
        },
    );
    assert!(query_result.is_err());

    let profile_result = encode_command(
        "command-001",
        &CommandPayload::InstallProfile {
            payload: b"bplist00".to_vec(),
        },
    );
    assert!(profile_result.is_err());
}

#[test]
fn accepts_a_minimal_configuration_profile_for_install() {
    let profile = enrollment_profile(&EnrollmentProfile {
        public_url: "https://mdm.example.test".into(),
        topic: "com.apple.mgmt.test".into(),
        challenge: "challenge".into(),
        enrollment_id: "enrollment-001".into(),
        ca_certificate: b"DER-CERTIFICATE".to_vec(),
        organization: "Example Org".into(),
    })
    .unwrap();

    assert!(
        encode_command(
            "command-001",
            &CommandPayload::InstallProfile { payload: profile },
        )
        .is_ok()
    );
}

#[test]
fn rejects_configuration_profiles_with_invalid_required_fields() {
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert("PayloadType".into(), Value::String("Configuration".into()));
    dictionary.insert(
        "PayloadIdentifier".into(),
        Value::String("com.example.profile".into()),
    );
    dictionary.insert("PayloadUUID".into(), Value::String("not-a-uuid".into()));
    dictionary.insert("PayloadVersion".into(), Value::Integer(1.into()));
    dictionary.insert("PayloadContent".into(), Value::Array(Vec::new()));
    let mut profile = Vec::new();
    Value::Dictionary(dictionary)
        .to_writer_xml(&mut profile)
        .unwrap();

    assert!(
        encode_command(
            "command-001",
            &CommandPayload::InstallProfile { payload: profile },
        )
        .is_err()
    );
}

#[test]
fn builds_device_only_enrollment_profile() {
    let encoded = enrollment_profile(&EnrollmentProfile {
        public_url: "https://mdm.example.test/".into(),
        topic: "com.apple.mgmt.test".into(),
        challenge: "enrollment-challenge".into(),
        enrollment_id: "enrollment-001".into(),
        ca_certificate: b"DER-CERTIFICATE".to_vec(),
        organization: "Example Org".into(),
    })
    .unwrap();
    let root = Value::from_reader(std::io::Cursor::new(encoded)).unwrap();
    let root_dict = root.as_dictionary().unwrap();
    assert_eq!(
        root_dict.get("PayloadType").and_then(Value::as_string),
        Some("Configuration")
    );
    let payloads = root_dict.get("PayloadContent").unwrap().as_array().unwrap();
    assert_eq!(payloads.len(), 3);

    let ca = payloads[0].as_dictionary().unwrap();
    assert_eq!(
        ca.get("PayloadType").and_then(Value::as_string),
        Some("com.apple.security.root")
    );
    assert_eq!(
        ca.get("PayloadContent").and_then(Value::as_data),
        Some(b"DER-CERTIFICATE".as_slice())
    );

    let scep = payloads[1].as_dictionary().unwrap();
    let scep_content = scep.get("PayloadContent").unwrap().as_dictionary().unwrap();
    assert_eq!(
        scep_content
            .get("Keysize")
            .and_then(Value::as_unsigned_integer),
        Some(2048)
    );
    assert_eq!(
        scep_content.get("Key Type").and_then(Value::as_string),
        Some("RSA")
    );
    assert_eq!(
        scep_content.get("Challenge").and_then(Value::as_string),
        Some("enrollment-challenge")
    );
    let subject = scep_content.get("Subject").unwrap().as_array().unwrap();
    assert_eq!(
        subject[0].as_array().unwrap()[0].as_array().unwrap()[0].as_string(),
        Some("CN")
    );
    assert_eq!(
        subject[0].as_array().unwrap()[0].as_array().unwrap()[1].as_string(),
        Some("enrollment-001")
    );

    let mdm = payloads[2].as_dictionary().unwrap();
    assert_eq!(
        mdm.get("AccessRights").and_then(Value::as_unsigned_integer),
        Some(4383)
    );
    assert_eq!(
        mdm.get("ServerURL").and_then(Value::as_string),
        Some("https://mdm.example.test/mdm")
    );
    assert_eq!(
        mdm.get("CheckInURL").and_then(Value::as_string),
        Some("https://mdm.example.test/checkin")
    );
    assert!(mdm.get("ServerCapabilities").is_none());
}
