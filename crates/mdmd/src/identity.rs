//! SCEP CA identity and certificate issuance.
//!
//! The implementation deliberately uses the OpenSSL PKCS#7 primitives instead of
//! a pre-existing MDM engine.  SCEP messages are untrusted input, so parsing is
//! bounded before handing bytes to OpenSSL and all required SCEP attributes are
//! checked before a certificate is issued.

use anyhow::{Context, Result, anyhow, bail};
use foreign_types::ForeignType;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{Id, PKey, Private};
use openssl::rand::rand_bytes;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509NameBuilder, X509PurposeRef, X509Ref, X509Req, X509StoreContext};
use openssl_sys as ffi;
use std::ffi::{CString, c_int, c_void};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

const MAX_SCEP_MESSAGE: usize = 1024 * 1024;
const MAX_CSR: usize = 4096;
const MAX_CHALLENGE: usize = 512;
const MAX_TRANSACTION_ID: usize = 256;
const MAX_NONCE: usize = 64;
const MIN_NONCE: usize = 16;
const CLIENT_CERT_DAYS: u32 = 365;
const CA_CERT_DAYS: u32 = 3650;

const OID_TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
const OID_MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
const OID_PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
const OID_SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
const OID_RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";

/// The parsed and authenticated pieces of one SCEP PKCSReq.
///
/// The DER fields are intentionally owned.  They keep the request independent
/// of OpenSSL's borrowed objects and let callers safely use this value across a
/// database transaction or an async boundary.
#[derive(Clone)]
pub struct ScepRequest {
    /// The CSR `challengePassword` attribute.
    pub challenge: String,
    /// SCEP transactionID, represented as its printable ASCII value.
    pub transaction_id: String,
    /// The request senderNonce.
    pub sender_nonce: Vec<u8>,
    /// DER encoded PKCS#10 request.
    pub csr_der: Vec<u8>,
    /// DER encoded self-signed certificate used to authenticate the request.
    pub requester_certificate_der: Vec<u8>,
    /// Exact authenticated request bytes, used for retransmission idempotency.
    pub request_der: Vec<u8>,
    /// The required CSR common name, copied from the authenticated CSR.
    pub subject_common_name: Option<String>,
}

/// A successful SCEP response and the newly issued certificate metadata.
#[derive(Clone)]
pub struct IssuedIdentity {
    /// SHA-256 fingerprint of the issued certificate, in lowercase hex.
    pub fingerprint: String,
    /// DER encoded, signed and encrypted SCEP CertRep response.
    pub response: Vec<u8>,
    /// The certificate's ASN.1 `notAfter` value.
    pub expires_at: String,
}

/// A CA identity used by the SCEP endpoints.
pub struct Identity {
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl Identity {
    /// Loads a CA certificate and its matching private key from PEM files.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = fs::read(cert_path)
            .with_context(|| format!("read CA certificate from {}", cert_path.display()))?;
        let key_pem = fs::read(key_path)
            .with_context(|| format!("read CA key from {}", key_path.display()))?;
        let key_mode = fs::metadata(key_path)
            .with_context(|| format!("stat CA key {}", key_path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if key_mode != 0o600 {
            bail!("CA key must have file mode 0600");
        }
        let certs = X509::stack_from_pem(&cert_pem).context("parse CA certificate PEM")?;
        if certs.len() != 1 {
            bail!("CA certificate PEM must contain exactly one certificate");
        }
        let ca_cert = certs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("CA certificate PEM is empty"))?;
        let ca_key = PKey::private_key_from_pem(&key_pem).context("parse CA private key PEM")?;
        if !ca_cert
            .public_key()
            .context("read CA public key")?
            .public_eq(&ca_key)
        {
            bail!("CA certificate and private key do not match");
        }
        let ca_public_key = ca_cert.public_key().context("read CA public key")?;
        if !ca_cert
            .verify(&ca_public_key)
            .context("verify CA self-signature")?
        {
            bail!("CA certificate is not self-signed");
        }
        ensure_valid_now(&ca_cert).context("CA certificate is not currently valid")?;
        Ok(Self { ca_cert, ca_key })
    }

    /// Creates a self-signed RSA CA certificate and a private key.
    ///
    /// Both paths are opened with `create_new`, so an existing file is never
    /// replaced.  The private key is written with mode 0600 before any bytes are
    /// written.
    pub fn initialize(cert_path: &Path, key_path: &Path) -> Result<()> {
        if cert_path == key_path {
            bail!("CA certificate and key paths must differ");
        }
        if cert_path.exists() || key_path.exists() {
            bail!("refusing to overwrite an existing CA certificate or key");
        }
        ensure_parent_directory(cert_path)?;
        ensure_parent_directory(key_path)?;

        let rsa = openssl::rsa::Rsa::generate(3072).context("generate CA RSA key")?;
        let ca_key = PKey::from_rsa(rsa).context("wrap CA RSA key")?;
        let mut name_builder = X509NameBuilder::new().context("create CA subject")?;
        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, "MDM SCEP CA")
            .context("set CA common name")?;
        let name = name_builder.build();

        let mut serial_bytes = [0u8; 20];
        rand_bytes(&mut serial_bytes).context("generate CA serial")?;
        serial_bytes[0] &= 0x7f;
        let serial_bn = BigNum::from_slice(&serial_bytes).context("create CA serial")?;
        let serial = Asn1Integer::from_bn(&serial_bn).context("encode CA serial")?;
        let not_before = Asn1Time::days_from_now(0).context("set CA notBefore")?;
        let not_after = Asn1Time::days_from_now(CA_CERT_DAYS).context("set CA notAfter")?;

        let mut builder = X509::builder().context("create CA certificate")?;
        builder.set_version(2).context("set CA version")?;
        builder
            .set_serial_number(&serial)
            .context("set CA serial")?;
        builder.set_subject_name(&name).context("set CA subject")?;
        builder.set_issuer_name(&name).context("set CA issuer")?;
        builder.set_pubkey(&ca_key).context("set CA public key")?;
        builder
            .set_not_before(&not_before)
            .context("set CA notBefore")?;
        builder
            .set_not_after(&not_after)
            .context("set CA notAfter")?;
        let mut constraints = BasicConstraints::new();
        constraints.critical().ca().pathlen(1);
        builder
            .append_extension(constraints.build().context("build CA constraints")?)
            .context("add CA constraints")?;
        let mut usage = KeyUsage::new();
        // This key is the combined SCEP CA/RA identity: it signs the CA
        // hierarchy and the SCEP CertRep SignedData response, and decrypts
        // the request EnvelopedData.
        usage
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .key_encipherment();
        builder
            .append_extension(usage.build().context("build CA key usage")?)
            .context("add CA key usage")?;
        {
            let context = builder.x509v3_context(None, None);
            builder
                .append_extension(
                    SubjectKeyIdentifier::new()
                        .build(&context)
                        .context("build CA subject key id")?,
                )
                .context("add CA subject key id")?;
        }
        builder
            .sign(&ca_key, MessageDigest::sha256())
            .context("sign CA certificate")?;
        let ca_cert = builder.build();

        let key_pem = ca_key
            .private_key_to_pem_pkcs8()
            .context("encode CA private key")?;
        let cert_pem = ca_cert.to_pem().context("encode CA certificate")?;

        write_new_file(key_path, &key_pem, 0o600)?;
        if let Err(err) = write_new_file(cert_path, &cert_pem, 0o644) {
            // The only path touched by this function was just created with
            // create_new; remove it so callers do not mistake a partial setup
            // for a usable CA.
            let _ = fs::remove_file(key_path);
            return Err(err);
        }
        Ok(())
    }

    /// Returns the CA certificate in DER form.
    pub fn ca_der(&self) -> Result<Vec<u8>> {
        self.ca_cert
            .to_der()
            .context("encode CA certificate as DER")
    }

    /// Returns the lowercase SHA-256 fingerprint of the CA certificate DER.
    pub fn ca_fingerprint(&self) -> Result<String> {
        Ok(hex::encode(hash(MessageDigest::sha256(), &self.ca_der()?)?))
    }

    /// Returns the CA certificate's ASN.1 `notAfter` value.
    pub fn certificate_expiry(&self) -> Result<String> {
        Ok(self.ca_cert.not_after().to_string())
    }

    /// Validates a client certificate received through the reverse proxy.
    ///
    /// The chain must terminate at this CA, be currently valid, and satisfy
    /// OpenSSL's TLS client-authentication purpose.  The returned value is the
    /// lowercase SHA-256 fingerprint of the leaf certificate DER.
    pub fn verify_client_certificate(&self, pem: &[u8]) -> Result<String> {
        if pem.len() > MAX_SCEP_MESSAGE {
            bail!("client certificate chain is too large");
        }
        let mut certs = X509::stack_from_pem(pem).context("parse client certificate PEM")?;
        if certs.is_empty() {
            bail!("client certificate PEM is empty");
        }
        let leaf = certs.remove(0);
        ensure_valid_now(&leaf).context("client certificate is not currently valid")?;

        let mut store_builder = X509StoreBuilder::new().context("create client CA store")?;
        store_builder
            .add_cert(self.ca_cert.clone())
            .context("add MDM CA to client store")?;
        let purpose_idx = X509PurposeRef::get_by_sname("sslclient")
            .context("look up SSL client certificate purpose")?;
        let purpose = X509PurposeRef::from_idx(purpose_idx)
            .context("load SSL client certificate purpose")?
            .purpose();
        store_builder
            .set_purpose(purpose)
            .context("set client certificate purpose")?;
        let store = store_builder.build();

        let mut chain = Stack::new().context("create client certificate chain")?;
        for cert in certs {
            chain
                .push(cert)
                .context("add client intermediate certificate")?;
        }
        let mut context = X509StoreContext::new().context("create client verification context")?;
        let verified = context
            .init(&store, &leaf, &chain, |ctx| ctx.verify_cert())
            .context("verify client certificate chain")?;
        if !verified {
            bail!("client certificate chain verification failed");
        }
        Ok(hex::encode(hash(
            MessageDigest::sha256(),
            &leaf.to_der().context("encode client certificate")?,
        )?))
    }

    /// Parses and authenticates a SCEP PKCSReq message.
    pub fn parse_request(&self, der: &[u8]) -> Result<ScepRequest> {
        if der.is_empty() || der.len() > MAX_SCEP_MESSAGE {
            bail!("SCEP request size is invalid");
        }
        // RFC 8894 PKCSReq is SignedData whose authenticated content is an
        // EnvelopedData object.  Accepting a bare SignedData CSR would allow a
        // caller to bypass the recipient encryption required by Apple SCEP.
        let message = Pkcs7::from_der(der).context("parse SCEP PKCS#7")?;
        if message.type_().map(|t| t.nid()) != Some(Nid::PKCS7_SIGNED) {
            bail!("SCEP request outer object is not SignedData");
        }

        let empty_certs = Stack::<X509>::new().context("create SCEP verifier certificate stack")?;
        // Inspect the authenticated signer certificate before invoking the
        // OpenSSL signature verifier.  This bounds RSA work from untrusted
        // PKCS#7 input and keeps the SCEP signer within the device-key policy.
        let signers = message
            .signers(&empty_certs, Pkcs7Flags::NOVERIFY)
            .context("read SCEP signer certificate")?;
        if signers.len() != 1 {
            bail!("SCEP request must contain exactly one signer certificate");
        }
        let requester = signers
            .get(0)
            .ok_or_else(|| anyhow!("SCEP signer certificate is missing"))?;
        let requester_key = requester
            .public_key()
            .context("read SCEP signer public key")?;
        validate_requester_key(&requester_key)?;

        let empty_store = X509StoreBuilder::new()
            .context("create SCEP verifier store")?
            .build();
        let mut enveloped_der = Vec::new();
        message
            .verify(
                &empty_certs,
                &empty_store,
                None,
                Some(&mut enveloped_der),
                Pkcs7Flags::NOVERIFY | Pkcs7Flags::BINARY,
            )
            .context("verify SCEP SignedData signature")?;
        if enveloped_der.is_empty() || enveloped_der.len() > MAX_SCEP_MESSAGE {
            bail!("SCEP EnvelopedData size is invalid");
        }
        let encrypted = Pkcs7::from_der(&enveloped_der).context("parse SCEP EnvelopedData")?;
        if encrypted.type_().map(|t| t.nid()) != Some(Nid::PKCS7_ENVELOPED) {
            bail!("SCEP SignedData content is not EnvelopedData");
        }
        let csr_der = encrypted
            .decrypt(&self.ca_key, &self.ca_cert, Pkcs7Flags::BINARY)
            .context("decrypt SCEP EnvelopedData")?;
        if csr_der.is_empty() || csr_der.len() > MAX_CSR {
            bail!("SCEP CSR size is invalid");
        }

        ensure_valid_now(requester).context("SCEP signer certificate is not currently valid")?;
        if !requester
            .verify(&requester_key)
            .context("verify SCEP signer self-signature")?
        {
            bail!("SCEP signer certificate is not self-signed");
        }

        let csr = X509Req::from_der(&csr_der).context("parse SCEP PKCS#10 request")?;
        let csr_key = csr.public_key().context("read SCEP CSR public key")?;
        if !csr.verify(&csr_key).context("verify SCEP CSR signature")? {
            bail!("SCEP CSR signature is invalid");
        }
        if !requester_key.public_eq(&csr_key) {
            bail!("SCEP signer certificate key does not match CSR key");
        }
        validate_csr_key(&csr_key)?;
        let challenge = csr_challenge(&csr).context("read SCEP challengePassword")?;
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE {
            bail!("SCEP challengePassword is invalid");
        }
        let transaction_id = signed_printable_attr(&message, OID_TRANSACTION_ID, "transactionID")?;
        if transaction_id.is_empty() || transaction_id.len() > MAX_TRANSACTION_ID {
            bail!("SCEP transactionID is invalid");
        }
        let message_type = signed_printable_attr(&message, OID_MESSAGE_TYPE, "messageType")?;
        if message_type != "19" {
            bail!("unsupported SCEP messageType");
        }
        let sender_nonce = signed_octet_attr(&message, OID_SENDER_NONCE, "senderNonce")?;
        if !(MIN_NONCE..=MAX_NONCE).contains(&sender_nonce.len()) {
            bail!("SCEP senderNonce length is invalid");
        }
        let requester_certificate_der = requester
            .to_der()
            .context("encode SCEP signer certificate")?;
        let subject_common_name = csr_common_name(&csr)?;
        Ok(ScepRequest {
            challenge,
            transaction_id,
            sender_nonce,
            csr_der,
            requester_certificate_der,
            request_der: der.to_vec(),
            subject_common_name: Some(subject_common_name),
        })
    }

    /// Issues a client certificate and returns the encrypted/signed SCEP CertRep.
    pub fn issue_response(
        &self,
        request: &ScepRequest,
        enrollment_id: &str,
    ) -> Result<IssuedIdentity> {
        if enrollment_id.is_empty()
            || enrollment_id.len() > MAX_TRANSACTION_ID
            || enrollment_id.chars().any(char::is_control)
        {
            bail!("enrollment identifier is invalid");
        }
        if request.request_der.is_empty() || request.request_der.len() > MAX_SCEP_MESSAGE {
            bail!("SCEP request bytes are invalid");
        }
        if request.challenge.is_empty()
            || request.challenge.len() > MAX_CHALLENGE
            || !request.challenge.is_ascii()
            || request
                .challenge
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            bail!("SCEP challengePassword is invalid");
        }
        if request.transaction_id.is_empty()
            || request.transaction_id.len() > MAX_TRANSACTION_ID
            || !request.transaction_id.is_ascii()
            || request
                .transaction_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            bail!("SCEP transactionID is invalid");
        }
        if !(MIN_NONCE..=MAX_NONCE).contains(&request.sender_nonce.len()) {
            bail!("SCEP senderNonce length is invalid");
        }
        if request.csr_der.is_empty()
            || request.csr_der.len() > MAX_CSR
            || request.requester_certificate_der.is_empty()
            || request.requester_certificate_der.len() > MAX_SCEP_MESSAGE
        {
            bail!("SCEP request fields exceed limits");
        }

        let csr = X509Req::from_der(&request.csr_der).context("parse SCEP CSR")?;
        let csr_key = csr.public_key().context("read SCEP CSR public key")?;
        if !csr.verify(&csr_key).context("verify SCEP CSR signature")? {
            bail!("SCEP CSR signature is invalid");
        }
        validate_csr_key(&csr_key)?;
        let common_name = csr_common_name(&csr)?;
        if common_name != enrollment_id
            || request.subject_common_name.as_deref() != Some(common_name.as_str())
        {
            bail!("CSR common name does not match enrollment identifier");
        }
        let requester = X509::from_der(&request.requester_certificate_der)
            .context("parse SCEP requester certificate")?;
        ensure_valid_now(&requester)
            .context("SCEP requester certificate is not currently valid")?;
        let requester_key = requester
            .public_key()
            .context("read SCEP requester public key")?;
        if !requester
            .verify(&requester_key)
            .context("verify SCEP requester self-signature")?
        {
            bail!("SCEP requester certificate is not self-signed");
        }
        if !requester_key.public_eq(&csr_key) {
            bail!("SCEP requester certificate key does not match CSR key");
        }
        let issued = self.issue_certificate(&csr, &csr_key, enrollment_id)?;
        let issued_der = issued.to_der().context("encode issued certificate")?;
        let fingerprint = hex::encode(hash(MessageDigest::sha256(), &issued_der)?);
        let certrep = certrep_message(&issued_der)?;

        let mut recipient_certs = Stack::new().context("create SCEP recipient stack")?;
        recipient_certs
            .push(requester.clone())
            .context("add SCEP requester certificate")?;
        let encrypted = Pkcs7::encrypt(
            &recipient_certs,
            &certrep,
            Cipher::aes_128_cbc(),
            Pkcs7Flags::BINARY,
        )
        .context("encrypt SCEP CertRep")?;
        let encrypted_der = encrypted
            .to_der()
            .context("encode encrypted SCEP CertRep")?;
        let signed_der = sign_scep_response(
            &self.ca_cert,
            &self.ca_key,
            &encrypted_der,
            &request.transaction_id,
            &request.sender_nonce,
        )?;
        let result = IssuedIdentity {
            fingerprint,
            response: signed_der,
            expires_at: issued.not_after().to_string(),
        };

        Ok(result)
    }

    fn issue_certificate(
        &self,
        csr: &X509Req,
        csr_key: &PKey<openssl::pkey::Public>,
        enrollment_id: &str,
    ) -> Result<X509> {
        let mut serial_bytes = [0u8; 20];
        rand_bytes(&mut serial_bytes).context("generate client certificate serial")?;
        serial_bytes[0] &= 0x7f;
        let serial_bn = BigNum::from_slice(&serial_bytes).context("create client serial")?;
        let serial = Asn1Integer::from_bn(&serial_bn).context("encode client serial")?;
        let not_before = Asn1Time::days_from_now(0).context("set client notBefore")?;
        let not_after = Asn1Time::days_from_now(CLIENT_CERT_DAYS).context("set client notAfter")?;
        if not_after
            .compare(self.ca_cert.not_after())
            .context("compare client and CA expiry")?
            == std::cmp::Ordering::Greater
        {
            bail!("CA certificate expires before the issued client certificate");
        }

        let mut builder = X509::builder().context("create client certificate")?;
        builder
            .set_version(2)
            .context("set client certificate version")?;
        builder
            .set_serial_number(&serial)
            .context("set client certificate serial")?;
        builder
            .set_subject_name(csr.subject_name())
            .context("set client certificate subject")?;
        builder
            .set_issuer_name(self.ca_cert.subject_name())
            .context("set client certificate issuer")?;
        builder
            .set_pubkey(csr_key)
            .context("set client certificate public key")?;
        builder
            .set_not_before(&not_before)
            .context("set client notBefore")?;
        builder
            .set_not_after(&not_after)
            .context("set client notAfter")?;
        let mut constraints = BasicConstraints::new();
        constraints.critical();
        builder
            .append_extension(constraints.build().context("build client constraints")?)
            .context("add client constraints")?;
        let mut usage = KeyUsage::new();
        usage.critical().digital_signature().key_encipherment();
        builder
            .append_extension(usage.build().context("build client key usage")?)
            .context("add client key usage")?;
        let mut eku = ExtendedKeyUsage::new();
        eku.client_auth();
        builder
            .append_extension(eku.build().context("build client EKU")?)
            .context("add client EKU")?;
        let subject_key_id = {
            let context = builder.x509v3_context(Some(&self.ca_cert), None);
            SubjectKeyIdentifier::new()
                .build(&context)
                .context("build client subject key id")?
        };
        builder
            .append_extension(subject_key_id)
            .context("add client subject key id")?;
        let authority_key_id = {
            let context = builder.x509v3_context(Some(&self.ca_cert), None);
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .issuer(false)
                .build(&context)
                .context("build client authority key id")?
        };
        builder
            .append_extension(authority_key_id)
            .context("add client authority key id")?;
        builder
            .sign(&self.ca_key, MessageDigest::sha256())
            .with_context(|| format!("sign client certificate for {}", enrollment_id))?;
        Ok(builder.build())
    }
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<()> {
    let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) else {
        return Ok(());
    };
    let mut missing = Vec::new();
    let mut current = parent;
    while !current.exists() {
        missing.push(current.to_owned());
        let Some(next) = current
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
        else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
    }
    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("protect directory {}", directory.display()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create directory {}", directory.display()));
            }
        }
    }
    Ok(())
}

fn ensure_valid_now(cert: &X509Ref) -> Result<()> {
    let now = Asn1Time::days_from_now(0).context("get current certificate time")?;
    if cert
        .not_before()
        .compare(&now)
        .context("compare certificate notBefore")?
        == std::cmp::Ordering::Greater
    {
        bail!("certificate is not yet valid");
    }
    if cert
        .not_after()
        .compare(&now)
        .context("compare certificate notAfter")?
        != std::cmp::Ordering::Greater
    {
        bail!("certificate has expired");
    }
    Ok(())
}

fn validate_csr_key(key: &PKey<openssl::pkey::Public>) -> Result<()> {
    validate_rsa_key(key, "SCEP CSR")?;
    Ok(())
}

fn validate_requester_key(key: &PKey<openssl::pkey::Public>) -> Result<()> {
    validate_rsa_key(key, "SCEP signer")?;
    Ok(())
}

fn validate_rsa_key(key: &PKey<openssl::pkey::Public>, label: &str) -> Result<()> {
    if key.id() != Id::RSA {
        bail!("{label} key must be RSA");
    }
    if key.bits() < 2048 {
        bail!("{label} RSA key must be at least 2048 bits");
    }
    if key.bits() > 4096 {
        bail!("{label} RSA key must be at most 4096 bits");
    }
    Ok(())
}

fn csr_common_name(csr: &X509Req) -> Result<String> {
    let mut names = csr.subject_name().entries_by_nid(Nid::COMMONNAME);
    let entry = names
        .next()
        .ok_or_else(|| anyhow!("SCEP CSR must contain a common name"))?;
    if names.next().is_some() {
        bail!("SCEP CSR must contain exactly one common name");
    }
    let common_name = entry
        .data()
        .to_string()
        .context("read SCEP CSR common name")?;
    if common_name.is_empty()
        || common_name.len() > MAX_TRANSACTION_ID
        || common_name.chars().any(char::is_control)
    {
        bail!("SCEP CSR common name is invalid");
    }
    Ok(common_name)
}

fn csr_challenge(csr: &X509Req) -> Result<String> {
    let challenge_nid = Nid::PKCS9_CHALLENGEPASSWORD.as_raw();
    let mut found = None;
    let count = unsafe { ffi::X509_REQ_get_attr_count(csr.as_ptr()) };
    if !(0..=128).contains(&count) {
        bail!("CSR attribute count is invalid");
    }
    for idx in 0..count {
        let attr = unsafe { ffi::X509_REQ_get_attr(csr.as_ptr(), idx) };
        if attr.is_null() {
            bail!("CSR contains a null attribute");
        }
        let object = unsafe { ffi::X509_ATTRIBUTE_get0_object(attr) };
        if object.is_null() || unsafe { ffi::OBJ_obj2nid(object) } != challenge_nid {
            continue;
        }
        if found.is_some() {
            bail!("CSR contains duplicate challengePassword attributes");
        }
        let value_count = unsafe { ffi::X509_ATTRIBUTE_count(attr) };
        if value_count != 1 {
            bail!("CSR challengePassword must contain exactly one value");
        }
        let value = unsafe { ffi::X509_ATTRIBUTE_get0_type(attr, 0) };
        found = Some(asn1_type_value(value, MAX_CHALLENGE)?);
    }
    let bytes = found.ok_or_else(|| anyhow!("CSR has no challengePassword"))?;
    printable_string(bytes, "challengePassword")
}

fn signed_printable_attr(message: &Pkcs7, oid: &str, label: &str) -> Result<String> {
    let value = signed_attr_value(message, oid, label, false)?;
    printable_string(value, label)
}

fn signed_octet_attr(message: &Pkcs7, oid: &str, label: &str) -> Result<Vec<u8>> {
    signed_attr_value(message, oid, label, true)
}

fn signed_attr_value(
    message: &Pkcs7,
    oid: &str,
    label: &str,
    require_octet: bool,
) -> Result<Vec<u8>> {
    let signer = signer_info(message)?;
    let nid = scep_nid(oid)?;
    let mut matching = 0;
    let attrs = unsafe { (*signer).auth_attr };
    if !attrs.is_null() {
        let count = unsafe { ffi::OPENSSL_sk_num(attrs as *const ffi::OPENSSL_STACK) };
        if !(0..=128).contains(&count) {
            bail!("SCEP signed attribute count is invalid");
        }
        for index in 0..count {
            let attr = unsafe {
                ffi::OPENSSL_sk_value(attrs as *const ffi::OPENSSL_STACK, index)
                    as *mut ffi::X509_ATTRIBUTE
            };
            if attr.is_null() {
                bail!("SCEP signed attribute is null");
            }
            let object = unsafe { ffi::X509_ATTRIBUTE_get0_object(attr) };
            if !object.is_null() && unsafe { ffi::OBJ_obj2nid(object) } == nid {
                matching += 1;
            }
        }
    }
    if matching != 1 {
        bail!("SCEP {} attribute must occur exactly once", label);
    }
    let attr = unsafe { ffi::PKCS7_get_signed_attribute(signer, nid) };
    if attr.is_null() {
        bail!("SCEP SignedData has no {} attribute", label);
    }
    let type_id = unsafe { (*attr).type_ };
    if require_octet && type_id != ffi::V_ASN1_OCTET_STRING {
        bail!("SCEP {} attribute is not an OCTET STRING", label);
    }
    if !require_octet
        && !matches!(
            type_id,
            ffi::V_ASN1_PRINTABLESTRING
                | ffi::V_ASN1_UTF8STRING
                | ffi::V_ASN1_IA5STRING
                | ffi::V_ASN1_T61STRING
        )
    {
        bail!("SCEP {} attribute has an unsupported ASN.1 type", label);
    }
    let value = unsafe { (*attr).value.asn1_string };
    asn1_string_value(value, MAX_TRANSACTION_ID.max(MAX_NONCE))
}

fn printable_string(value: Vec<u8>, label: &str) -> Result<String> {
    if value.is_empty() || value.iter().any(|byte| byte.is_ascii_control()) {
        bail!("{} is empty or contains control characters", label);
    }
    let value = String::from_utf8(value).with_context(|| format!("{} is not UTF-8", label))?;
    if !value.is_ascii() {
        bail!("{} must contain ASCII characters", label);
    }
    Ok(value)
}

fn asn1_string_value(value: *mut ffi::ASN1_STRING, max_len: usize) -> Result<Vec<u8>> {
    if value.is_null() {
        bail!("ASN.1 attribute value is missing");
    }
    let len = unsafe { ffi::ASN1_STRING_length(value) };
    if len < 0 || len as usize > max_len {
        bail!("ASN.1 attribute value is too large");
    }
    let data = unsafe { ffi::ASN1_STRING_get0_data(value) };
    if len > 0 && data.is_null() {
        bail!("ASN.1 attribute value has no data");
    }
    Ok(if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len as usize) }.to_vec()
    })
}

fn asn1_type_value(value: *mut ffi::ASN1_TYPE, max_len: usize) -> Result<Vec<u8>> {
    if value.is_null() {
        bail!("ASN.1 attribute value is missing");
    }
    let type_id = unsafe { (*value).type_ };
    if !matches!(
        type_id,
        ffi::V_ASN1_PRINTABLESTRING
            | ffi::V_ASN1_UTF8STRING
            | ffi::V_ASN1_IA5STRING
            | ffi::V_ASN1_T61STRING
    ) {
        bail!("ASN.1 string attribute has an unsupported type");
    }
    let string = unsafe { (*value).value.asn1_string };
    asn1_string_value(string, max_len)
}

fn signer_info(message: &Pkcs7) -> Result<*mut ffi::PKCS7_SIGNER_INFO> {
    let infos = unsafe { ffi::PKCS7_get_signer_info(message.as_ptr()) };
    if infos.is_null() {
        bail!("SCEP SignedData has no signer info");
    }
    let count = unsafe { ffi::OPENSSL_sk_num(infos as *const ffi::OPENSSL_STACK) };
    if count != 1 {
        bail!("SCEP SignedData must contain exactly one signer info");
    }
    let signer = unsafe {
        ffi::OPENSSL_sk_value(infos as *const ffi::OPENSSL_STACK, 0) as *mut ffi::PKCS7_SIGNER_INFO
    };
    if signer.is_null() {
        bail!("SCEP signer info is null");
    }
    Ok(signer)
}

fn scep_nid(oid: &str) -> Result<c_int> {
    static TRANSACTION: OnceLock<c_int> = OnceLock::new();
    static MESSAGE: OnceLock<c_int> = OnceLock::new();
    static STATUS: OnceLock<c_int> = OnceLock::new();
    static SENDER: OnceLock<c_int> = OnceLock::new();
    static RECIPIENT: OnceLock<c_int> = OnceLock::new();
    let slot = match oid {
        OID_TRANSACTION_ID => &TRANSACTION,
        OID_MESSAGE_TYPE => &MESSAGE,
        OID_PKI_STATUS => &STATUS,
        OID_SENDER_NONCE => &SENDER,
        OID_RECIPIENT_NONCE => &RECIPIENT,
        _ => bail!("unsupported SCEP attribute OID"),
    };
    if let Some(nid) = slot.get() {
        return Ok(*nid);
    }
    let oid_c = CString::new(oid).context("encode SCEP attribute OID")?;
    let object = unsafe { ffi::OBJ_txt2obj(oid_c.as_ptr(), 1) };
    let known = if object.is_null() {
        ffi::NID_undef
    } else {
        let nid = unsafe { ffi::OBJ_obj2nid(object) };
        unsafe { ffi::ASN1_OBJECT_free(object) };
        nid
    };
    let nid = if known != ffi::NID_undef {
        known
    } else {
        let short = CString::new(match oid {
            OID_TRANSACTION_ID => "scepTransactionID",
            OID_MESSAGE_TYPE => "scepMessageType",
            OID_PKI_STATUS => "scepPKIStatus",
            OID_SENDER_NONCE => "scepSenderNonce",
            OID_RECIPIENT_NONCE => "scepRecipientNonce",
            _ => unreachable!(),
        })?;
        let long = CString::new(format!("SCEP {}", oid))?;
        let created = unsafe { ffi::OBJ_create(oid_c.as_ptr(), short.as_ptr(), long.as_ptr()) };
        if created == ffi::NID_undef {
            bail!("OpenSSL could not register SCEP attribute OID");
        }
        created
    };
    let _ = slot.set(nid);
    Ok(nid)
}

fn certrep_message(certificate_der: &[u8]) -> Result<Vec<u8>> {
    if certificate_der.is_empty() || certificate_der.len() > MAX_CSR {
        bail!("issued certificate size is invalid");
    }
    // CertRepMessage ::= SEQUENCE { response SEQUENCE OF CertResponse }
    // CertResponse ::= SEQUENCE {
    //   certReqId INTEGER, status PKIStatus,
    //   certificate [0] EXPLICIT Certificate OPTIONAL }
    let cert = der_tlv(0xa0, certificate_der);
    let mut response_fields = Vec::with_capacity(3 + 3 + cert.len());
    response_fields.extend_from_slice(&[0x02, 0x01, 0x00]);
    response_fields.extend_from_slice(&[0x02, 0x01, 0x00]);
    response_fields.extend_from_slice(&cert);
    let response = der_tlv(0x30, &response_fields);
    let responses = der_tlv(0x30, &response);
    Ok(der_tlv(0x30, &responses))
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + 5 + value.len());
    output.push(tag);
    der_length(value.len(), &mut output);
    output.extend_from_slice(value);
    output
}

fn der_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
    } else {
        let mut bytes = [0u8; std::mem::size_of::<usize>()];
        let mut value = length;
        let mut count = 0;
        while value != 0 {
            bytes[bytes.len() - 1 - count] = (value & 0xff) as u8;
            value >>= 8;
            count += 1;
        }
        output.push(0x80 | count as u8);
        output.extend_from_slice(&bytes[bytes.len() - count..]);
    }
}

fn sign_scep_response(
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    encrypted_der: &[u8],
    transaction_id: &str,
    recipient_nonce: &[u8],
) -> Result<Vec<u8>> {
    if transaction_id.is_empty() || transaction_id.len() > MAX_TRANSACTION_ID {
        bail!("SCEP response transactionID is invalid");
    }
    if !(MIN_NONCE..=MAX_NONCE).contains(&recipient_nonce.len()) {
        bail!("SCEP response recipientNonce length is invalid");
    }
    let mut sender_nonce = [0u8; 16];
    rand_bytes(&mut sender_nonce).context("generate SCEP response senderNonce")?;
    let transaction_nid = scep_nid(OID_TRANSACTION_ID)?;
    let message_nid = scep_nid(OID_MESSAGE_TYPE)?;
    let status_nid = scep_nid(OID_PKI_STATUS)?;
    let sender_nid = scep_nid(OID_SENDER_NONCE)?;
    let recipient_nid = scep_nid(OID_RECIPIENT_NONCE)?;

    let raw = unsafe { ffi::PKCS7_new() };
    if raw.is_null() {
        return Err(anyhow!(openssl::error::ErrorStack::get()))
            .context("create SCEP response PKCS#7");
    }
    let p7 = unsafe { Pkcs7::from_ptr(raw) };
    let result = (|| -> Result<Vec<u8>> {
        unsafe {
            if ffi::PKCS7_set_type(p7.as_ptr(), ffi::NID_pkcs7_signed) <= 0 {
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("set SCEP response type");
            }
            if ffi::PKCS7_add_certificate(p7.as_ptr(), ca_cert.as_ptr()) <= 0 {
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("add SCEP CA certificate");
            }
            let signer = ffi::PKCS7_add_signature(
                p7.as_ptr(),
                ca_cert.as_ptr(),
                ca_key.as_ptr(),
                MessageDigest::sha256().as_ptr(),
            );
            if signer.is_null() {
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("add SCEP response signer");
            }
            add_printable_attr(signer, transaction_nid, transaction_id)?;
            add_printable_attr(signer, message_nid, "3")?;
            add_printable_attr(signer, status_nid, "0")?;
            add_octet_attr(signer, sender_nid, &sender_nonce)?;
            add_octet_attr(signer, recipient_nid, recipient_nonce)?;
            if ffi::PKCS7_content_new(p7.as_ptr(), ffi::NID_pkcs7_data) <= 0 {
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("create SCEP response content");
            }
            let bio = ffi::PKCS7_dataInit(p7.as_ptr(), ptr::null_mut());
            if bio.is_null() {
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("initialize SCEP response content");
            }
            let mut written = 0usize;
            while written < encrypted_der.len() {
                let remaining = encrypted_der.len() - written;
                let chunk_len = remaining.min(c_int::MAX as usize) as c_int;
                let count = ffi::BIO_write(
                    bio,
                    encrypted_der[written..].as_ptr() as *const c_void,
                    chunk_len,
                );
                if count <= 0 {
                    ffi::BIO_free_all(bio);
                    return Err(anyhow!(openssl::error::ErrorStack::get()))
                        .context("write SCEP response content");
                }
                written += count as usize;
            }
            if ffi::PKCS7_dataFinal(p7.as_ptr(), bio) <= 0 {
                ffi::BIO_free_all(bio);
                return Err(anyhow!(openssl::error::ErrorStack::get()))
                    .context("finalize SCEP response signature");
            }
            ffi::BIO_free_all(bio);
        }
        p7.to_der().context("encode SCEP response SignedData")
    })();
    if result.is_err() {
        // `p7` owns the raw PKCS7 object and will release it here.
    }
    result
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn add_printable_attr(
    signer: *mut ffi::PKCS7_SIGNER_INFO,
    nid: c_int,
    value: &str,
) -> Result<()> {
    let value_ptr = ffi::ASN1_STRING_type_new(ffi::V_ASN1_PRINTABLESTRING);
    if value_ptr.is_null() {
        return Err(anyhow!(openssl::error::ErrorStack::get()))
            .context("allocate SCEP printable attribute");
    }
    if ffi::ASN1_STRING_set(
        value_ptr,
        value.as_bytes().as_ptr() as *const c_void,
        value.len() as c_int,
    ) <= 0
    {
        ffi::ASN1_STRING_free(value_ptr);
        return Err(anyhow!(openssl::error::ErrorStack::get()))
            .context("set SCEP printable attribute");
    }
    if ffi::PKCS7_add_signed_attribute(
        signer,
        nid,
        ffi::V_ASN1_PRINTABLESTRING,
        value_ptr as *mut c_void,
    ) <= 0
    {
        ffi::ASN1_STRING_free(value_ptr);
        return Err(anyhow!(openssl::error::ErrorStack::get()))
            .context("add SCEP printable attribute");
    }
    // OpenSSL takes ownership of the ASN1 value on success.
    Ok(())
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn add_octet_attr(
    signer: *mut ffi::PKCS7_SIGNER_INFO,
    nid: c_int,
    value: &[u8],
) -> Result<()> {
    let value_ptr = ffi::ASN1_OCTET_STRING_new();
    if value_ptr.is_null() {
        return Err(anyhow!(openssl::error::ErrorStack::get()))
            .context("allocate SCEP octet attribute");
    }
    if value.len() > c_int::MAX as usize
        || ffi::ASN1_OCTET_STRING_set(value_ptr, value.as_ptr(), value.len() as c_int) <= 0
    {
        ffi::ASN1_OCTET_STRING_free(value_ptr);
        return Err(anyhow!(openssl::error::ErrorStack::get())).context("set SCEP octet attribute");
    }
    if ffi::PKCS7_add_signed_attribute(
        signer,
        nid,
        ffi::V_ASN1_OCTET_STRING,
        value_ptr as *mut c_void,
    ) <= 0
    {
        ffi::ASN1_OCTET_STRING_free(value_ptr);
        return Err(anyhow!(openssl::error::ErrorStack::get())).context("add SCEP octet attribute");
    }
    // OpenSSL takes ownership of the ASN1 value on success.
    Ok(())
}
