use anyhow::{Context, Result, anyhow, ensure};
use foreign_types::ForeignType;
use mdmd::identity::Identity;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509NameBuilder, X509Req};
use openssl_sys as ffi;
use std::ffi::{CString, c_int, c_void};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::ptr;
use tempfile::tempdir;

const TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
const MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
const PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
const SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
const RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";

fn oid_nid(oid: &str) -> Result<c_int> {
    let oid_c = CString::new(oid)?;
    let object = unsafe { ffi::OBJ_txt2obj(oid_c.as_ptr(), 1) };
    if !object.is_null() {
        let nid = unsafe { ffi::OBJ_obj2nid(object) };
        unsafe { ffi::ASN1_OBJECT_free(object) };
        if nid > 0 {
            return Ok(nid);
        }
    }
    let short = CString::new(format!(
        "mdmTest{}",
        oid.rsplit('.').next().unwrap_or("oid")
    ))?;
    let long = CString::new(format!("MDM test {oid}"))?;
    let nid = unsafe { ffi::OBJ_create(oid_c.as_ptr(), short.as_ptr(), long.as_ptr()) };
    if nid > 0 {
        return Ok(nid);
    }
    // Another test or the identity implementation may have registered this
    // process-global OID between the lookup and OBJ_create call.
    let object = unsafe { ffi::OBJ_txt2obj(oid_c.as_ptr(), 1) };
    ensure!(!object.is_null(), "register SCEP OID");
    let nid = unsafe { ffi::OBJ_obj2nid(object) };
    unsafe { ffi::ASN1_OBJECT_free(object) };
    ensure!(nid > 0, "register SCEP OID");
    Ok(nid)
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn add_printable_attribute(
    signer: *mut ffi::PKCS7_SIGNER_INFO,
    nid: c_int,
    value: &str,
) -> Result<()> {
    let string = ffi::ASN1_STRING_type_new(ffi::V_ASN1_PRINTABLESTRING);
    ensure!(!string.is_null(), "allocate SCEP attribute");
    ensure!(
        ffi::ASN1_STRING_set(
            string,
            value.as_bytes().as_ptr() as *const c_void,
            value.len() as c_int,
        ) > 0,
        "set SCEP attribute"
    );
    ensure!(
        ffi::PKCS7_add_signed_attribute(
            signer,
            nid,
            ffi::V_ASN1_PRINTABLESTRING,
            string as *mut c_void,
        ) > 0,
        "add SCEP attribute"
    );
    Ok(())
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn add_octet_attribute(
    signer: *mut ffi::PKCS7_SIGNER_INFO,
    nid: c_int,
    value: &[u8],
) -> Result<()> {
    let octets = ffi::ASN1_OCTET_STRING_new();
    ensure!(!octets.is_null(), "allocate SCEP nonce");
    ensure!(
        ffi::ASN1_OCTET_STRING_set(octets, value.as_ptr(), value.len() as c_int) > 0,
        "set SCEP nonce"
    );
    ensure!(
        ffi::PKCS7_add_signed_attribute(
            signer,
            nid,
            ffi::V_ASN1_OCTET_STRING,
            octets as *mut c_void,
        ) > 0,
        "add SCEP nonce"
    );
    Ok(())
}

fn signed_message(
    content: &[u8],
    signer_certificate: &X509,
    signer_key: &PKey<Private>,
    transaction_id: &str,
    sender_nonce: &[u8],
) -> Result<Vec<u8>> {
    let raw = unsafe { ffi::PKCS7_new() };
    ensure!(!raw.is_null(), "allocate SignedData");
    let message = unsafe { Pkcs7::from_ptr(raw) };
    unsafe {
        ensure!(
            ffi::PKCS7_set_type(message.as_ptr(), ffi::NID_pkcs7_signed) > 0,
            "set SignedData type"
        );
        ensure!(
            ffi::PKCS7_add_certificate(message.as_ptr(), signer_certificate.as_ptr()) > 0,
            "add signer certificate"
        );
        let signer = ffi::PKCS7_add_signature(
            message.as_ptr(),
            signer_certificate.as_ptr(),
            signer_key.as_ptr(),
            MessageDigest::sha256().as_ptr(),
        );
        ensure!(!signer.is_null(), "add SCEP signature");
        add_printable_attribute(signer, oid_nid(MESSAGE_TYPE)?, "19")?;
        add_printable_attribute(signer, oid_nid(TRANSACTION_ID)?, transaction_id)?;
        add_octet_attribute(signer, oid_nid(SENDER_NONCE)?, sender_nonce)?;
        ensure!(
            ffi::PKCS7_content_new(message.as_ptr(), ffi::NID_pkcs7_data) > 0,
            "create SignedData content"
        );
        let bio = ffi::PKCS7_dataInit(message.as_ptr(), ptr::null_mut());
        ensure!(!bio.is_null(), "initialize SignedData content");
        ensure!(
            ffi::BIO_write(
                bio,
                content.as_ptr() as *const c_void,
                content.len() as c_int
            ) == content.len() as c_int,
            "write SignedData content"
        );
        ensure!(
            ffi::PKCS7_dataFinal(message.as_ptr(), bio) > 0,
            "finalize SignedData"
        );
        ffi::BIO_free_all(bio);
    }
    message.to_der().context("encode SignedData")
}

fn csr(cn: &str, challenge: Option<&str>, key: &PKey<Private>) -> Result<Vec<u8>> {
    let mut subject = X509NameBuilder::new().context("create CSR subject")?;
    subject.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let subject = subject.build();
    let raw = unsafe { ffi::X509_REQ_new() };
    ensure!(!raw.is_null(), "allocate CSR");
    let request = unsafe { X509Req::from_ptr(raw) };
    unsafe {
        ensure!(
            ffi::X509_REQ_set_version(request.as_ptr(), 0) > 0,
            "set CSR version"
        );
        ensure!(
            ffi::X509_REQ_set_subject_name(request.as_ptr(), subject.as_ptr()) > 0,
            "set CSR subject"
        );
        ensure!(
            ffi::X509_REQ_set_pubkey(request.as_ptr(), key.as_ptr()) > 0,
            "set CSR public key"
        );
        if let Some(challenge) = challenge {
            ensure!(
                ffi::X509_REQ_add1_attr_by_NID(
                    request.as_ptr(),
                    Nid::PKCS9_CHALLENGEPASSWORD.as_raw(),
                    ffi::V_ASN1_PRINTABLESTRING,
                    challenge.as_bytes().as_ptr(),
                    challenge.len() as c_int,
                ) > 0,
                "add CSR challengePassword"
            );
        }
        ensure!(
            ffi::X509_REQ_sign(
                request.as_ptr(),
                key.as_ptr(),
                MessageDigest::sha256().as_ptr(),
            ) > 0,
            "sign CSR"
        );
    }
    request.to_der().context("encode CSR")
}

fn self_signed_certificate(cn: &str, key: &PKey<Private>, serial_number: u32) -> Result<X509> {
    let mut subject = X509NameBuilder::new().context("create signer subject")?;
    subject.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let subject = subject.build();
    let serial_bn = BigNum::from_u32(serial_number)?;
    let serial = Asn1Integer::from_bn(&serial_bn)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(30)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}

fn encrypt_for(recipient: &X509, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut recipients = Stack::new()?;
    recipients.push(recipient.clone())?;
    Ok(Pkcs7::encrypt(
        &recipients,
        plaintext,
        Cipher::aes_128_cbc(),
        Pkcs7Flags::BINARY,
    )?
    .to_der()?)
}

fn take_tlv(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    ensure!(input.len() >= 2 && input[0] == tag, "unexpected DER tag");
    let first = input[1];
    let (length, header_len) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let bytes = (first & 0x7f) as usize;
        ensure!(
            bytes > 0 && bytes <= std::mem::size_of::<usize>(),
            "invalid DER length"
        );
        ensure!(input.len() >= 2 + bytes, "truncated DER length");
        let mut length = 0usize;
        for byte in &input[2..2 + bytes] {
            length = length
                .checked_shl(8)
                .and_then(|value| value.checked_add(*byte as usize))
                .ok_or_else(|| anyhow!("DER length overflow"))?;
        }
        (length, 2 + bytes)
    };
    ensure!(
        header_len <= input.len() && length <= input.len() - header_len,
        "truncated DER value"
    );
    Ok((
        &input[header_len..header_len + length],
        &input[header_len + length..],
    ))
}

fn certificate_from_certrep(certrep: &[u8]) -> Result<Vec<u8>> {
    let (outer, rest) = take_tlv(certrep, 0x30)?;
    ensure!(rest.is_empty(), "trailing CertRep bytes");
    let (responses, rest) = take_tlv(outer, 0x30)?;
    ensure!(rest.is_empty(), "trailing CertRep response bytes");
    let (response, rest) = take_tlv(responses, 0x30)?;
    ensure!(rest.is_empty(), "trailing CertResponse bytes");
    let (_, response) = take_tlv(response, 0x02)?;
    let (_, response) = take_tlv(response, 0x02)?;
    let (certificate, rest) = take_tlv(response, 0xa0)?;
    ensure!(rest.is_empty(), "trailing certificate response fields");
    Ok(certificate.to_vec())
}

fn signed_attribute(message: &Pkcs7, oid: &str) -> Result<(c_int, Vec<u8>)> {
    let signer_infos = unsafe { ffi::PKCS7_get_signer_info(message.as_ptr()) };
    ensure!(!signer_infos.is_null(), "response has no signer info");
    let count = unsafe { ffi::OPENSSL_sk_num(signer_infos as *const ffi::OPENSSL_STACK) };
    ensure!(count == 1, "response has unexpected signer count");
    let signer = unsafe {
        ffi::OPENSSL_sk_value(signer_infos as *const ffi::OPENSSL_STACK, 0)
            as *mut ffi::PKCS7_SIGNER_INFO
    };
    ensure!(!signer.is_null(), "response signer is null");
    let nid = oid_nid(oid)?;
    let attribute = unsafe { ffi::PKCS7_get_signed_attribute(signer, nid) };
    ensure!(!attribute.is_null(), "response attribute is missing");
    let type_id = unsafe { (*attribute).type_ };
    let value = unsafe { (*attribute).value.asn1_string };
    ensure!(!value.is_null(), "response attribute value is missing");
    let length = unsafe { ffi::ASN1_STRING_length(value) };
    ensure!(length >= 0, "response attribute length is invalid");
    let data = unsafe { ffi::ASN1_STRING_get0_data(value) };
    ensure!(
        length == 0 || !data.is_null(),
        "response attribute data is missing"
    );
    let bytes = if length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, length as usize) }.to_vec()
    };
    Ok((type_id, bytes))
}

#[test]
fn scep_nested_roundtrip_and_rejections() -> Result<()> {
    let directory = tempdir()?;
    let ca_directory = directory.path().join("data");
    let ca_certificate = ca_directory.join("ca.pem");
    let ca_key = ca_directory.join("ca-key.pem");
    Identity::initialize(&ca_certificate, &ca_key)?;
    assert_eq!(
        fs::metadata(&ca_directory)?.permissions().mode() & 0o777,
        0o700
    );
    let identity = Identity::load(&ca_certificate, &ca_key)?;
    let ca = X509::from_der(&identity.ca_der()?)?;

    let requester_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let requester_certificate = self_signed_certificate("enroll-1", &requester_key, 1)?;
    let request_csr = csr("enroll-1", Some("test-challenge"), &requester_key)?;
    let encrypted_csr = encrypt_for(&ca, &request_csr)?;
    let sender_nonce = b"0123456789abcdef";
    let request_der = signed_message(
        &encrypted_csr,
        &requester_certificate,
        &requester_key,
        "transaction-1",
        sender_nonce,
    )?;

    let request = identity.parse_request(&request_der)?;
    assert_eq!(request.challenge, "test-challenge");
    assert_eq!(request.transaction_id, "transaction-1");
    assert_eq!(request.sender_nonce, sender_nonce);
    let issued = identity.issue_response(&request, "enroll-1")?;

    let response = Pkcs7::from_der(&issued.response)?;
    let (message_type_kind, message_type) = signed_attribute(&response, MESSAGE_TYPE)?;
    assert_eq!(message_type_kind, ffi::V_ASN1_PRINTABLESTRING);
    assert_eq!(message_type, b"3");
    let (status_kind, status) = signed_attribute(&response, PKI_STATUS)?;
    assert_eq!(status_kind, ffi::V_ASN1_PRINTABLESTRING);
    assert_eq!(status, b"0");
    let (transaction_kind, transaction) = signed_attribute(&response, TRANSACTION_ID)?;
    assert_eq!(transaction_kind, ffi::V_ASN1_PRINTABLESTRING);
    assert_eq!(transaction, b"transaction-1");
    let (recipient_kind, recipient_nonce) = signed_attribute(&response, RECIPIENT_NONCE)?;
    assert_eq!(recipient_kind, ffi::V_ASN1_OCTET_STRING);
    assert_eq!(recipient_nonce, sender_nonce);
    let (sender_kind, response_sender_nonce) = signed_attribute(&response, SENDER_NONCE)?;
    assert_eq!(sender_kind, ffi::V_ASN1_OCTET_STRING);
    assert_eq!(response_sender_nonce.len(), 16);
    assert_ne!(response_sender_nonce.as_slice(), sender_nonce);

    let empty_certs = Stack::<X509>::new()?;
    let empty_store = X509StoreBuilder::new()?.build();
    let mut encrypted_response = Vec::new();
    response.verify(
        &empty_certs,
        &empty_store,
        None,
        Some(&mut encrypted_response),
        Pkcs7Flags::NOVERIFY | Pkcs7Flags::BINARY,
    )?;
    let encrypted_response = Pkcs7::from_der(&encrypted_response)?;
    assert_eq!(
        encrypted_response.type_().map(|value| value.nid()),
        Some(Nid::PKCS7_ENVELOPED)
    );
    let certrep =
        encrypted_response.decrypt(&requester_key, &requester_certificate, Pkcs7Flags::BINARY)?;
    let issued_certificate = X509::from_der(&certificate_from_certrep(&certrep)?)?;
    let issued_certificate_pem = issued_certificate.to_pem()?;
    assert_eq!(
        identity.verify_client_certificate(&issued_certificate_pem)?,
        issued.fingerprint
    );
    let unrelated_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let unrelated_certificate = self_signed_certificate("unrelated", &unrelated_key, 2)?;
    assert!(
        identity
            .verify_client_certificate(&unrelated_certificate.to_pem()?)
            .is_err()
    );

    // A top-level EnvelopedData and an unencrypted bare SignedData CSR are
    // rejected; Apple SCEP requires SignedData containing EnvelopedData.
    assert!(
        identity
            .parse_request(&encrypt_for(&ca, &request_der)?)
            .is_err()
    );
    let bare_signed = signed_message(
        &request_csr,
        &requester_certificate,
        &requester_key,
        "transaction-1",
        sender_nonce,
    )?;
    assert!(identity.parse_request(&bare_signed).is_err());

    // Signature tampering and a CSR signature tampered inside a fresh valid
    // outer SignedData must both be detected.
    let mut bad_signer = request_der.clone();
    *bad_signer.last_mut().context("empty SignedData")? ^= 1;
    assert!(identity.parse_request(&bad_signer).is_err());
    let mut bad_csr = request_csr.clone();
    *bad_csr.last_mut().context("empty CSR")? ^= 1;
    let bad_csr_request = signed_message(
        &encrypt_for(&ca, &bad_csr)?,
        &requester_certificate,
        &requester_key,
        "transaction-1",
        sender_nonce,
    )?;
    assert!(identity.parse_request(&bad_csr_request).is_err());

    // The signer certificate and CSR must carry the same RSA key, and the
    // CSR must include a challengePassword and the enrollment CN.
    let other_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let other_certificate = self_signed_certificate("enroll-1", &other_key, 3)?;
    let mismatched_signer = signed_message(
        &encrypted_csr,
        &other_certificate,
        &other_key,
        "transaction-1",
        sender_nonce,
    )?;
    assert!(identity.parse_request(&mismatched_signer).is_err());
    let no_challenge_csr = csr("enroll-1", None, &requester_key)?;
    let no_challenge_request = signed_message(
        &encrypt_for(&ca, &no_challenge_csr)?,
        &requester_certificate,
        &requester_key,
        "transaction-1",
        sender_nonce,
    )?;
    assert!(identity.parse_request(&no_challenge_request).is_err());
    assert!(
        identity
            .issue_response(&request, "different-enrollment")
            .is_err()
    );
    let unrelated_key_path = directory.path().join("unrelated-key.pem");
    fs::write(
        &unrelated_key_path,
        unrelated_key.private_key_to_pem_pkcs8()?,
    )?;
    fs::set_permissions(&unrelated_key_path, fs::Permissions::from_mode(0o600))?;
    assert!(Identity::load(&ca_certificate, &unrelated_key_path).is_err());
    Ok(())
}
