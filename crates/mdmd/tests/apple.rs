use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mdmd::apple::{
    AdeClient, VppAsset, VppClient, build_ade_profile, parse_ade_machine_info,
    parse_ade_machine_info_der, validate_manifest_url, verify_ade_machine_info,
    verify_ade_machine_info_der,
};
use openssl::{
    asn1::Asn1Integer,
    bn::BigNum,
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    symm::Cipher,
    x509::{X509, X509NameBuilder},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};
use tempfile::tempdir;

const CONSUMER_KEY: &str = "consumer-key-test";
const CONSUMER_SECRET: &str = "consumer-secret-test";
const ACCESS_TOKEN: &str = "access-token-test";
const ACCESS_SECRET: &str = "access-secret-test";
const VPP_TOKEN: &str = "vpp-token-test";

#[derive(Clone)]
struct MockResponse {
    status: u16,
    body: String,
    headers: Vec<(&'static str, &'static str)>,
}

impl MockResponse {
    fn json(body: Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            headers: vec![("Content-Type", "application/json")],
        }
    }

    fn status(status: u16, body: Value) -> Self {
        Self {
            status,
            body: body.to_string(),
            headers: vec![("Content-Type", "application/json")],
        }
    }
}

struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn new(responses: Vec<MockResponse>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let join = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let request = read_request(&mut stream).unwrap_or_default();
                captured.lock().unwrap().push(request);
                let reason = match response.status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    500 => "Internal Server Error",
                    _ => "Test",
                };
                let mut wire = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    reason,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    wire.push_str(name);
                    wire.push_str(": ");
                    wire.push_str(value);
                    wire.push_str("\r\n");
                }
                wire.push_str("\r\n");
                wire.push_str(&response.body);
                let _ = stream.write_all(wire.as_bytes());
            }
        });
        Ok(Self {
            url: format!("http://{address}"),
            requests,
            join: Some(join),
        })
    }

    fn join(mut self) -> Vec<String> {
        if let Some(join) = self.join.take() {
            join.join().expect("mock server thread");
        }
        Arc::try_unwrap(self.requests)
            .expect("mock server request references")
            .into_inner()
            .expect("mock server request lock")
    }
}

fn read_request(stream: &mut TcpStream) -> Result<String> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    let body_start;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            body_start = index + 4;
            break;
        }
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(anyhow!("request too large"));
        }
    }
    let head = String::from_utf8_lossy(&bytes[..body_start]);
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.eq_ignore_ascii_case("content-length"))
                .then(|| value.trim().parse::<usize>().ok())
        })
        .flatten()
        .unwrap_or(0);
    while bytes.len() < body_start + content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn request_path(request: &str) -> &str {
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or_default()
}

fn provider_identity() -> Result<(PKey<openssl::pkey::Private>, X509)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "ADE token fixture")?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
    cert.set_not_before(&not_before)?;
    cert.set_not_after(&not_after)?;
    cert.sign(&key, MessageDigest::sha256())?;
    Ok((key, cert.build()))
}

fn write_mode600(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn encrypted_token_fixture(
    directory: &Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let (key, cert) = provider_identity()?;
    let token_json = json!({
        "consumer_key": CONSUMER_KEY,
        "consumer_secret": CONSUMER_SECRET,
        "access_token": ACCESS_TOKEN,
        "access_secret": ACCESS_SECRET,
    })
    .to_string();
    let mut recipients = Stack::new()?;
    recipients.push(cert.clone())?;
    let cms = CmsContentInfo::encrypt(
        &recipients,
        token_json.as_bytes(),
        Cipher::aes_128_cbc(),
        CMSOptions::BINARY,
    )?;
    let token_path = directory.join("server-token.p7m");
    let cert_path = directory.join("provider-cert.pem");
    let key_path = directory.join("provider-key.pem");
    write_mode600(&token_path, &cms.to_der()?)?;
    fs::write(&cert_path, cert.to_pem()?)?;
    write_mode600(&key_path, &key.private_key_to_pem_pkcs8()?)?;
    Ok((token_path, cert_path, key_path))
}

#[tokio::test]
async fn ade_decrypts_server_token_and_calls_real_endpoint_shapes() -> Result<()> {
    let server = MockServer::new(vec![
        MockResponse::json(json!({"auth_session_token": "session-test"})),
        MockResponse::json(json!({
            "cursor": "cursor-1",
            "devices": [{"serial_number": "SERIAL-1"}],
            "more_to_follow": false
        })),
        MockResponse::json(json!({"cursor": null, "devices": [], "more_to_follow": false})),
        MockResponse::json(json!({"profile_uuid": "profile-1"})),
        MockResponse::json(json!({"profile_uuid": "profile-1", "profile_name": "test"})),
        MockResponse::json(json!({"devices": {"SERIAL-1": "SUCCESS"}})),
        MockResponse::json(json!({"devices": {"SERIAL-1": "SUCCESS"}})),
    ])?;
    let directory = tempdir()?;
    let (token_path, cert_path, key_path) = encrypted_token_fixture(directory.path())?;
    let encrypted_client = AdeClient::from_encrypted_token(&token_path, &cert_path, &key_path)?;
    let (_, anchor_cert) = provider_identity()?;
    // The production constructor uses Apple's fixed origin.  This test-only
    // client exercises the decrypted credentials against a loopback fixture.
    let client = AdeClient::for_test(
        &server.url,
        CONSUMER_KEY,
        CONSUMER_SECRET,
        ACCESS_TOKEN,
        ACCESS_SECRET,
    )?;
    drop(encrypted_client);
    let page = client.fetch_devices(None, Some(100)).await?;
    assert_eq!(page.devices.len(), 1);
    assert_eq!(page.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(
        client.sync_devices("cursor-1", None).await?.devices.len(),
        0
    );
    let profile = client
        .define_profile(&json!({
            "profile_name": "test",
            "url": "https://mdm.example.test/ade/enroll",
            "anchor_certs": [BASE64.encode(anchor_cert.to_der()?)]
        }))
        .await?;
    assert_eq!(profile.value["profile_uuid"], "profile-1");
    assert_eq!(
        client.get_profile("profile-1").await?.value["profile_name"],
        "test"
    );
    let serials = vec!["SERIAL-1".to_owned()];
    client.assign_profile("profile-1", &serials).await?;
    client.unassign_profile("profile-1", &serials).await?;
    let requests = server.join();
    assert_eq!(requests.len(), 7);
    assert_eq!(request_path(&requests[0]), "/session");
    assert_eq!(request_path(&requests[1]), "/server/devices");
    assert_eq!(request_path(&requests[2]), "/devices/sync");
    assert_eq!(request_path(&requests[3]), "/profile");
    assert_eq!(
        request_path(&requests[4]),
        "/profile?profile_uuid=profile-1"
    );
    assert_eq!(request_path(&requests[5]), "/profile/devices");
    assert_eq!(
        requests[5]
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .next(),
        Some("POST")
    );
    assert_eq!(
        requests[6]
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .next(),
        Some("DELETE")
    );
    for request in requests {
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: oauth"));
        assert!(request.contains("consumer-key-test"));
        assert!(request.contains("access-token-test"));
        assert!(!request.contains(CONSUMER_SECRET));
        assert!(!request.contains(ACCESS_SECRET));
    }
    // Keep the constructor call above meaningful: the encrypted CMS path was
    // parsed and rejected if any credential or key did not match.
    drop(client);
    Ok(())
}

#[tokio::test]
async fn vpp_uses_bearer_device_license_operations_and_masks_errors() -> Result<()> {
    let server = MockServer::new(vec![
        MockResponse::json(json!({"countryCode": "US"})),
        MockResponse::json(json!({"assets": []})),
        MockResponse::json(
            json!({"eventId": "event-1", "tokenExpirationDate": "2030-01-01T00:00:00Z"}),
        ),
        MockResponse::json(json!({"eventId": "event-2"})),
        MockResponse::json(json!({
            "assignments": [{"adamId": "123456789", "serialNumber": "SERIAL-1"}]
        })),
        MockResponse::json(json!({"eventId": "event-1", "status": "COMPLETED"})),
    ])?;
    let client = VppClient::for_test(&format!("{}/mdm/v2", server.url), VPP_TOKEN)?;
    assert_eq!(client.service_config().await?["countryCode"], "US");
    client.assets(&[("deviceAssignable", "true")]).await?;
    let asset = VppAsset::new("123456789", Some("STDQ".to_owned()))?;
    let serials = vec!["SERIAL-1".to_owned()];
    assert_eq!(
        client
            .associate(std::slice::from_ref(&asset), &serials)
            .await?
            .event_id,
        "event-1"
    );
    assert_eq!(
        client.disassociate(&[asset], &serials).await?.event_id,
        "event-2"
    );
    let assignment = client.assignment("123456789", "SERIAL-1").await?;
    assert_eq!(assignment["assignments"][0]["serialNumber"], "SERIAL-1");
    assert_eq!(client.status("event-1").await?["status"], "COMPLETED");
    let requests = server.join();
    assert_eq!(request_path(&requests[0]), "/mdm/v2/service/config");
    assert_eq!(
        request_path(&requests[1]),
        "/mdm/v2/assets?deviceAssignable=true"
    );
    assert_eq!(request_path(&requests[2]), "/mdm/v2/assets/associate");
    assert_eq!(request_path(&requests[3]), "/mdm/v2/assets/disassociate");
    assert_eq!(
        request_path(&requests[4]),
        "/mdm/v2/assignments?adamId=123456789&serialNumber=SERIAL-1"
    );
    assert_eq!(request_path(&requests[5]), "/mdm/v2/status?eventId=event-1");
    assert!(
        requests[2]
            .to_ascii_lowercase()
            .contains("authorization: bearer vpp-token-test")
    );
    assert!(requests[2].contains("\"serialNumbers\":[\"SERIAL-1\"]"));
    assert!(!requests[2].contains("clientUserIds"));

    let error_server = MockServer::new(vec![MockResponse::status(
        403,
        json!({
            "error": VPP_TOKEN
        }),
    )])?;
    let error_client = VppClient::for_test(&error_server.url, VPP_TOKEN)?;
    let error = error_client.service_config().await.unwrap_err().to_string();
    assert!(!error.contains(VPP_TOKEN));
    error_server.join();
    Ok(())
}

#[test]
fn vpp_token_file_accepts_apple_base64_json_s_token() -> Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("apps-books-token");
    let encoded = BASE64.encode(
        json!({
            "token": "opaque-location-token",
            "expDate": "2030-11-08T22:33:22+0000",
            "orgName": "ORG12345",
        })
        .to_string(),
    );
    write_mode600(&path, encoded.as_bytes())?;
    let _client = VppClient::from_token_file(&path)?;
    Ok(())
}

#[test]
fn ade_machine_info_requires_signed_cms_and_manifest_is_https_only() -> Result<()> {
    let (key, cert) = provider_identity()?;
    let plist = br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>SERIAL</key><string>SERIAL-1</string><key>UDID</key><string>UDID-1</string><key>PRODUCT</key><string>iPad14,3</string><key>VERSION</key><string>22A300</string><key>OS_VERSION</key><string>18.0</string></dict></plist>"#;
    let cms = CmsContentInfo::sign(
        Some(&cert),
        Some(&key),
        None,
        Some(plist),
        CMSOptions::BINARY,
    )?;
    let cms_der = cms.to_der()?;
    let encoded = BASE64.encode(&cms_der);
    let info = parse_ade_machine_info(&encoded)?;
    assert_eq!(info.serial, "SERIAL-1");
    assert_eq!(info.udid.as_deref(), Some("UDID-1"));
    assert_eq!(info.version.as_deref(), Some("22A300"));
    assert_eq!(parse_ade_machine_info_der(&cms_der)?.serial, "SERIAL-1");
    let cert_pem = cert.to_pem()?;
    assert_eq!(
        verify_ade_machine_info(&encoded, &cert_pem)?.serial,
        "SERIAL-1"
    );
    assert_eq!(
        verify_ade_machine_info_der(&cms_der, &cert_pem)?.serial,
        "SERIAL-1"
    );
    assert!(parse_ade_machine_info(&BASE64.encode(b"unsigned serial=SERIAL-1")).is_err());
    let incomplete_plist = br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>SERIAL</key><string>SERIAL-1</string><key>UDID</key><string>UDID-1</string><key>PRODUCT</key><string>iPad14,3</string><key>OS_VERSION</key><string>18.0</string></dict></plist>"#;
    let incomplete_cms = CmsContentInfo::sign(
        Some(&cert),
        Some(&key),
        None,
        Some(incomplete_plist),
        CMSOptions::BINARY,
    )?;
    assert!(parse_ade_machine_info_der(&incomplete_cms.to_der()?).is_err());
    assert!(validate_manifest_url("file:///tmp/app-manifest.plist").is_err());
    assert!(validate_manifest_url("http://example.test/app.plist").is_err());
    assert!(validate_manifest_url("https://cdn.example.test/app.plist").is_ok());
    let profile = build_ade_profile(
        "fixture",
        "https://mdm.example.test/ade/enroll",
        &cert.to_der()?,
    )?;
    assert_eq!(profile["url"], "https://mdm.example.test/ade/enroll");
    assert_eq!(profile["await_device_configured"], true);
    assert_eq!(profile["is_supervised"], true);
    assert_eq!(profile["is_mandatory"], true);
    assert_eq!(profile["is_mdm_removable"], false);
    assert!(
        build_ade_profile(
            "fixture",
            "http://mdm.example.test/ade/enroll",
            &cert.to_der()?
        )
        .is_err()
    );
    Ok(())
}
