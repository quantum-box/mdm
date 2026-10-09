//! Apple Push Notification service adapter for MDM push messages.

use anyhow::{Context, Result, anyhow, bail};
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509;
use reqwest::{Client, Identity as ReqwestIdentity, StatusCode, Version, redirect::Policy};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

const APNS_ENDPOINT: &str = "https://api.push.apple.com/3/device/";
const MAX_IDENTITY_PEM: usize = 1024 * 1024;
const MAX_TOPIC_LEN: usize = 256;
const MAX_PUSH_MAGIC_LEN: usize = 1024;

/// An APNs client authenticated with an Apple MDM client certificate.
pub struct ApnsClient {
    client: Client,
    topic: String,
}

/// The result of one APNs push attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// APNs accepted the push. `apns_id` is present when APNs returned one.
    Accepted { apns_id: Option<String> },
    /// The request can be retried after the transport or APNs condition clears.
    Retry { reason: String },
    /// APNs rejected the request permanently for this token or payload.
    Rejected { reason: String },
}

impl ApnsClient {
    /// Loads a PEM identity and configures a production APNs HTTP/2 client.
    ///
    /// The PEM may contain a leaf certificate, intermediates, and a private key.
    /// The leaf's `UID` subject attribute must exactly equal `topic`; this avoids
    /// accidentally sending an MDM push through a certificate issued for another
    /// tenant or environment.
    pub fn new(identity_pem: &Path, topic: &str) -> Result<Self> {
        if !topic.starts_with("com.apple.mgmt.")
            || topic.is_empty()
            || topic.len() > MAX_TOPIC_LEN
            || !topic.is_ascii()
        {
            bail!("APNs topic is invalid");
        }
        let pem = fs::read(identity_pem)
            .with_context(|| format!("read APNs identity from {}", identity_pem.display()))?;
        let identity_mode = fs::metadata(identity_pem)
            .with_context(|| format!("stat APNs identity {}", identity_pem.display()))?
            .permissions()
            .mode()
            & 0o777;
        if identity_mode != 0o600 {
            bail!("APNs identity must have file mode 0600");
        }
        if pem.is_empty() || pem.len() > MAX_IDENTITY_PEM {
            bail!("APNs identity PEM is empty or too large");
        }
        let certs = X509::stack_from_pem(&pem).context("parse APNs identity certificates")?;
        if certs.is_empty() {
            bail!("APNs identity PEM has no certificate");
        }
        let leaf = certs[0].clone();
        ensure_valid_now(&leaf).context("APNs identity certificate is not currently valid")?;
        let uid = leaf
            .subject_name()
            .entries_by_nid(Nid::USERID)
            .next()
            .map(|entry| entry.data().to_string())
            .transpose()
            .context("read APNs identity certificate UID")?;
        if uid.as_deref() != Some(topic) {
            bail!("APNs certificate UID does not match topic");
        }
        let key = PKey::private_key_from_pem(&pem).context("parse APNs identity private key")?;
        let leaf_key = leaf.public_key().context("read APNs identity public key")?;
        if !leaf_key.public_eq(&key) {
            bail!("APNs identity certificate and private key do not match");
        }
        let cert_pem = certs.iter().try_fold(Vec::new(), |mut output, cert| {
            output.extend_from_slice(&cert.to_pem().context("encode APNs certificate")?);
            Ok::<_, anyhow::Error>(output)
        })?;
        let key_pem = key
            .private_key_to_pem_pkcs8()
            .context("encode APNs private key")?;
        let reqwest_identity = ReqwestIdentity::from_pkcs8_pem(&cert_pem, &key_pem)
            .map_err(|_| anyhow!("invalid APNs TLS identity"))?;
        let client = Client::builder()
            .use_native_tls()
            .https_only(true)
            .identity(reqwest_identity)
            .redirect(Policy::none())
            .http2_adaptive_window(true)
            .timeout(Duration::from_secs(15))
            .build()
            .context("build APNs HTTP/2 client")?;
        Ok(Self {
            client,
            topic: topic.to_owned(),
        })
    }

    /// Sends an MDM push containing only the Apple `mdm` push magic.
    pub async fn send(&self, token: &[u8], push_magic: &str) -> Result<PushOutcome> {
        if token.is_empty() || token.len() > 256 {
            bail!("APNs device token is invalid");
        }
        if push_magic.is_empty() || push_magic.len() > MAX_PUSH_MAGIC_LEN || !push_magic.is_ascii()
        {
            bail!("APNs push magic is invalid");
        }
        let token_hex = hex::encode(token);
        let url = format!("{}{}", APNS_ENDPOINT, token_hex);
        let payload = serde_json::json!({ "mdm": push_magic });
        let response = match self
            .client
            .post(url)
            .version(Version::HTTP_2)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "mdm")
            .header("apns-priority", "10")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => {
                return Ok(PushOutcome::Retry {
                    reason: "APNs transport request failed".to_owned(),
                });
            }
        };

        if response.version() != Version::HTTP_2 {
            return Ok(PushOutcome::Retry {
                reason: "APNs HTTP/2 negotiation failed".to_owned(),
            });
        }

        let apns_id = response
            .headers()
            .get("apns-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let status = response.status();
        if status == StatusCode::OK {
            return Ok(PushOutcome::Accepted { apns_id });
        }

        // APNs reasons are short, token-independent identifiers.  Keep only a
        // bounded printable value from the JSON error object and never include
        // the request URL, token, certificate, or transport error text.
        let reason = response
            .json::<Value>()
            .await
            .ok()
            .and_then(|body| {
                body.get("reason")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 128
                    && value.is_ascii()
                    && value.bytes().all(|byte| !byte.is_ascii_control())
            })
            .unwrap_or_else(|| format!("APNs HTTP {}", status.as_u16()));

        if status == StatusCode::FORBIDDEN
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status.is_server_error()
        {
            Ok(PushOutcome::Retry { reason })
        } else {
            Ok(PushOutcome::Rejected { reason })
        }
    }
}

fn ensure_valid_now(cert: &X509) -> Result<()> {
    let now = Asn1Time::days_from_now(0).context("get current certificate time")?;
    if cert
        .not_before()
        .compare(&now)
        .context("compare APNs identity notBefore")?
        == std::cmp::Ordering::Greater
    {
        bail!("APNs identity certificate is not yet valid");
    }
    if cert
        .not_after()
        .compare(&now)
        .context("compare APNs identity notAfter")?
        != std::cmp::Ordering::Greater
    {
        bail!("APNs identity certificate has expired");
    }
    Ok(())
}
