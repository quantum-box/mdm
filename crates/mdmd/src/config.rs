use anyhow::{Result, bail};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone)]
pub struct Config {
    pub database: PathBuf,
    pub bind: SocketAddr,
    pub public_url: String,
    pub topic: String,
    pub organization: String,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub apns_identity: Option<PathBuf>,
    pub admin_token: String,
    pub read_token: Option<String>,
    pub trust_proxy: bool,
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
        if self.tls_cert.is_none() && !self.bind.ip().is_loopback() {
            bail!("plaintext backend must bind to loopback; configure TLS for public binding");
        }
        let url = reqwest::Url::parse(&self.public_url)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("public URL must be an HTTPS origin without path, query, or credentials");
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
