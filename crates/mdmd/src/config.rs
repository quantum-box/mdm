use anyhow::{Result, bail};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone)]
pub struct Config {
    pub database: PathBuf,
    pub bind: SocketAddr,
    pub public_url: String,
    pub bootstrap_url: Option<String>,
    pub topic: String,
    pub organization: String,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub apns_identity: Option<PathBuf>,
    pub admin_token: String,
    pub read_token: Option<String>,
    pub trust_proxy: bool,
    pub gateway_key_file: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            bail!("TLS certificate and key must be configured together");
        }
        if self.tls_cert.is_some() && self.trust_proxy {
            bail!("use either built-in TLS or trusted TLS proxy mode");
        }
        if self.trust_proxy && self.gateway_key_file.is_some() {
            bail!("use either trusted TLS proxy mode or gateway authentication");
        }
        if self.tls_cert.is_none() && !self.bind.ip().is_loopback() {
            bail!("plaintext backend must bind to loopback; configure TLS for public binding");
        }
        validate_origin(&self.public_url, "public URL")?;
        if let Some(url) = &self.bootstrap_url {
            validate_origin(url, "bootstrap URL")?;
        }
        if !self.topic.starts_with("com.apple.mgmt.")
            || self.topic.len() > 255
            || self
                .topic
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || !self.topic.is_ascii()
        {
            bail!("topic must be the com.apple.mgmt.* UID from the Apple MDM Push certificate");
        }
        for token in std::iter::once(&self.admin_token).chain(self.read_token.iter()) {
            if token.len() < 32 || token.chars().any(char::is_whitespace) {
                bail!("management tokens must have at least 32 characters without whitespace");
            }
        }
        if self.read_token.as_ref() == Some(&self.admin_token) {
            bail!("read-only and admin tokens must be different");
        }
        if self.organization.is_empty()
            || self.organization.len() > 255
            || self.organization.chars().any(char::is_control)
        {
            bail!("organization must have 1 to 255 bytes");
        }
        Ok(())
    }
}

fn validate_origin(value: &str, label: &str) -> Result<()> {
    // Reject raw paths and controls before URL parsing normalizes dot segments
    // or backslashes. The profile builder receives this original string.
    let authority = value
        .strip_prefix("https://")
        .filter(|_| !value.chars().any(|c| c.is_control() || c.is_whitespace()))
        .filter(|authority| !authority.trim_end_matches('/').contains(['/', '\\', '@']))
        .ok_or_else(|| anyhow::anyhow!("{label} must be an HTTPS origin"))?;
    if authority.is_empty() {
        bail!("{label} must contain a hostname");
    }
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("{label} must be an HTTPS origin without path, query, or credentials");
    }
    Ok(())
}
