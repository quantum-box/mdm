use anyhow::{Context, Result, bail, ensure};
use mdmd::{
    config::Config,
    http::App,
    identity::Identity,
    storage::{self, IssuedCertificate, Store},
    tls,
};
use openssl::{
    asn1::Asn1Integer,
    bn::BigNum,
    hash::{MessageDigest, hash},
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use reqwest::StatusCode;
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::oneshot, time::sleep};

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    directory: TempDir,
    app: App,
    server_certificate: PathBuf,
    server_key: PathBuf,
    server_pem: Vec<u8>,
    client_certificate_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    wrong_client_certificate_pem: Vec<u8>,
    wrong_client_key_pem: Vec<u8>,
    expired_client_certificate_pem: Vec<u8>,
    expired_client_key_pem: Vec<u8>,
}

fn self_signed_ca(common_name: &str, serial_number: u32) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", common_name)?;
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(serial_number)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(2)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    let mut constraints = BasicConstraints::new();
    constraints.critical().ca();
    builder.append_extension(constraints.build()?)?;
    let mut usage = KeyUsage::new();
    usage.critical().key_cert_sign().crl_sign();
    builder.append_extension(usage.build()?)?;
    builder.sign(&key, MessageDigest::sha256())?;
    Ok((builder.build(), key))
}

fn signed_client_certificate(
    ca: &X509,
    ca_key: &PKey<Private>,
    common_name: &str,
    serial_number: u32,
) -> Result<(X509, PKey<Private>)> {
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(1)?;
    signed_client_certificate_with_validity(
        ca,
        ca_key,
        common_name,
        serial_number,
        &not_before,
        &not_after,
    )
}

fn signed_client_certificate_with_validity(
    ca: &X509,
    ca_key: &PKey<Private>,
    common_name: &str,
    serial_number: u32,
    not_before: &openssl::asn1::Asn1TimeRef,
    not_after: &openssl::asn1::Asn1TimeRef,
) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", common_name)?;
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(serial_number)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(ca.subject_name())?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(not_before)?;
    builder.set_not_after(not_after)?;
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    builder.append_extension(constraints.build()?)?;
    let mut usage = KeyUsage::new();
    usage.critical().digital_signature().key_encipherment();
    builder.append_extension(usage.build()?)?;
    let mut eku = ExtendedKeyUsage::new();
    eku.client_auth();
    builder.append_extension(eku.build()?)?;
    builder.sign(ca_key, MessageDigest::sha256())?;
    Ok((builder.build(), key))
}

fn server_certificate() -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", "localhost")?;
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(100)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(1)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    builder.append_extension(constraints.build()?)?;
    let mut usage = KeyUsage::new();
    usage.critical().digital_signature().key_encipherment();
    builder.append_extension(usage.build()?)?;
    let mut eku = ExtendedKeyUsage::new();
    eku.server_auth();
    builder.append_extension(eku.build()?)?;
    let mut san = SubjectAlternativeName::new();
    san.dns("localhost").ip("127.0.0.1");
    let context = builder.x509v3_context(None, None);
    builder.append_extension(san.build(&context)?)?;
    builder.sign(&key, MessageDigest::sha256())?;
    Ok((builder.build(), key))
}

fn write_private_key(path: &Path, key: &PKey<Private>) -> Result<()> {
    fs::write(path, key.private_key_to_pem_pkcs8()?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn fixture() -> Result<Fixture> {
    let directory = tempfile::tempdir()?;
    let ca_certificate_path = directory.path().join("ca.pem");
    let ca_key_path = directory.path().join("ca-key.pem");
    Identity::initialize(&ca_certificate_path, &ca_key_path)?;
    let identity = Arc::new(Identity::load(&ca_certificate_path, &ca_key_path)?);
    let ca = X509::from_der(&identity.ca_der()?)?;
    let ca_key = PKey::private_key_from_pem(&fs::read(&ca_key_path)?)?;

    let (server, server_key) = server_certificate()?;
    let server_certificate_path = directory.path().join("server.pem");
    let server_key_path = directory.path().join("server-key.pem");
    let server_pem = server.to_pem()?;
    fs::write(&server_certificate_path, &server_pem)?;
    write_private_key(&server_key_path, &server_key)?;

    let (client, client_key) = signed_client_certificate(&ca, &ca_key, "tls-device", 200)?;
    let client_certificate_pem = client.to_pem()?;
    let client_key_pem = client_key.private_key_to_pem_pkcs8()?;
    let (wrong_ca, wrong_ca_key) = self_signed_ca("wrong-ca", 300)?;
    let (wrong_client, wrong_client_key) =
        signed_client_certificate(&wrong_ca, &wrong_ca_key, "wrong-device", 301)?;
    let wrong_client_certificate_pem = wrong_client.to_pem()?;
    let wrong_client_key_pem = wrong_client_key.private_key_to_pem_pkcs8()?;
    let expired_not_before = openssl::asn1::Asn1Time::from_unix((storage::now() - 7200) as _)?;
    let expired_not_after = openssl::asn1::Asn1Time::from_unix((storage::now() - 3600) as _)?;
    let (expired_client, expired_client_key) = signed_client_certificate_with_validity(
        &ca,
        &ca_key,
        "expired-device",
        302,
        &expired_not_before,
        &expired_not_after,
    )?;
    let expired_client_certificate_pem = expired_client.to_pem()?;
    let expired_client_key_pem = expired_client_key.private_key_to_pem_pkcs8()?;

    let database = directory.path().join("mdm.sqlite");
    let store = Store::open(&database)?;
    let fingerprint = hex::encode(hash(MessageDigest::sha256(), &client.to_der()?)?);
    let enrollment_id = store.create_enrollment("tls-challenge", storage::now())?;
    let issued =
        store.issue_identity("tls-challenge", "tls-test-request", storage::now(), |_| {
            Ok(IssuedCertificate {
                fingerprint,
                expires_at: client.not_after().to_string(),
                response: Vec::new(),
            })
        })?;
    ensure!(issued.is_empty());
    ensure!(!enrollment_id.is_empty());

    let config = Config {
        database,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        public_url: "https://localhost".into(),
        bootstrap_url: None,
        topic: "com.apple.mgmt.test".into(),
        organization: "TLS Test".into(),
        ca_cert: ca_certificate_path,
        ca_key: ca_key_path,
        apns_identity: None,
        admin_token: ADMIN_TOKEN.into(),
        read_token: None,
        trust_proxy: false,
        gateway_key_file: None,
        tls_cert: Some(server_certificate_path.clone()),
        tls_key: Some(server_key_path.clone()),
    };
    config.validate()?;
    Ok(Fixture {
        directory,
        app: App {
            config,
            store,
            identity,
        },
        server_certificate: server_certificate_path,
        server_key: server_key_path,
        server_pem,
        client_certificate_pem,
        client_key_pem,
        wrong_client_certificate_pem,
        wrong_client_key_pem,
        expired_client_certificate_pem,
        expired_client_key_pem,
    })
}

fn client(root_certificate: &[u8], identity: Option<(&[u8], &[u8])>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_native_tls()
        .https_only(true)
        .http2_adaptive_window(true)
        .add_root_certificate(reqwest::Certificate::from_pem(root_certificate)?);
    if let Some((certificate, key)) = identity {
        builder = builder.identity(reqwest::Identity::from_pkcs8_pem(certificate, key)?);
    }
    Ok(builder.build()?)
}

async fn wait_for_health(client: &reqwest::Client, address: SocketAddr) -> Result<()> {
    let url = format!("https://localhost:{}/health", address.port());
    for _ in 0..100 {
        if let Ok(response) = client.get(&url).send().await {
            ensure!(response.status() == StatusCode::OK);
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    bail!("TLS server did not become ready")
}

fn authenticate_body() -> Vec<u8> {
    br#"<?xml version="1.0"?><plist version="1.0"><dict>
      <key>MessageType</key><string>Authenticate</string>
      <key>UDID</key><string>tls-udid</string>
      <key>Topic</key><string>com.apple.mgmt.test</string>
      <key>SerialNumber</key><string>TLS-TEST</string>
      <key>OSVersion</key><string>18.0</string>
    </dict></plist>"#
        .to_vec()
}

#[tokio::test]
async fn native_tls_authenticates_clients_and_keeps_bootstrap_routes_open() -> Result<()> {
    let fixture = fixture()?;
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let app = fixture.app.clone();
    let server_certificate = fixture.server_certificate.clone();
    let server_key = fixture.server_key.clone();
    let server = tokio::spawn(async move {
        tls::serve(
            listener,
            app,
            &server_certificate,
            &server_key,
            async move {
                let _ = shutdown_receiver.await;
            },
        )
        .await
    });

    let anonymous = client(&fixture.server_pem, None)?;
    wait_for_health(&anonymous, address).await?;
    let health: serde_json::Value = anonymous
        .get(format!("https://localhost:{}/health", address.port()))
        .send()
        .await?
        .json()
        .await?;
    ensure!(health["status"] == "ok");
    let ca_caps = anonymous
        .get(format!(
            "https://localhost:{}/scep?operation=GetCACaps",
            address.port()
        ))
        .send()
        .await?;
    ensure!(ca_caps.status() == StatusCode::OK);
    ensure!(ca_caps.text().await?.contains("POSTPKIOperation"));
    let ca_certificate = anonymous
        .get(format!(
            "https://localhost:{}/scep?operation=GetCACert",
            address.port()
        ))
        .send()
        .await?;
    ensure!(ca_certificate.status() == StatusCode::OK);
    ensure!(!ca_certificate.bytes().await?.is_empty());
    let enroll = anonymous
        .post(format!(
            "https://localhost:{}/v1/enrollments",
            address.port()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?;
    ensure!(enroll.status() == StatusCode::OK);

    // An anonymous TLS connection always carries AuthenticatedTlsPeer(None, 0),
    // so forwarded headers cannot spoof a device certificate.
    let spoofed = anonymous
        .put(format!("https://localhost:{}/checkin", address.port()))
        .header("x-mdm-client-verify", "SUCCESS")
        .header("x-mdm-client-cert", "%6e%6f%74%2d%61%2d%63%65%72%74")
        .body(authenticate_body())
        .send()
        .await?;
    ensure!(spoofed.status() == StatusCode::UNAUTHORIZED);

    let authenticated = client(
        &fixture.server_pem,
        Some((&fixture.client_certificate_pem, &fixture.client_key_pem)),
    )?;
    let checkin = authenticated
        .put(format!("https://localhost:{}/checkin", address.port()))
        .body(authenticate_body())
        .send()
        .await?;
    ensure!(checkin.status() == StatusCode::OK);

    let wrong_identity = client(
        &fixture.server_pem,
        Some((
            &fixture.wrong_client_certificate_pem,
            &fixture.wrong_client_key_pem,
        )),
    )?;
    ensure!(
        wrong_identity
            .get(format!("https://localhost:{}/health", address.port()))
            .send()
            .await
            .is_err()
    );

    let expired_identity = client(
        &fixture.server_pem,
        Some((
            &fixture.expired_client_certificate_pem,
            &fixture.expired_client_key_pem,
        )),
    )?;
    ensure!(
        expired_identity
            .get(format!("https://localhost:{}/health", address.port()))
            .send()
            .await
            .is_err()
    );

    drop(expired_identity);
    drop(wrong_identity);
    drop(authenticated);
    drop(spoofed);
    drop(enroll);
    drop(anonymous);
    drop(health);
    shutdown_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("shutdown receiver dropped"))?;
    tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .context("native TLS server did not stop")???;
    drop(fixture.directory);
    Ok(())
}
