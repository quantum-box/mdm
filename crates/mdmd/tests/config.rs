use mdmd::config::Config;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn config(
    bind: SocketAddr,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    trust_proxy: bool,
) -> Config {
    Config {
        database: PathBuf::from("data/mdm.sqlite"),
        bind,
        public_url: "https://mdm.example.test".to_owned(),
        topic: "com.apple.mgmt.test".to_owned(),
        organization: "Test Organization".to_owned(),
        ca_cert: PathBuf::from("data/ca.pem"),
        ca_key: PathBuf::from("data/ca-key.pem"),
        apns_identity: None,
        admin_token: ADMIN_TOKEN.to_owned(),
        read_token: None,
        trust_proxy,
        tls_cert: tls_cert.map(PathBuf::from),
        tls_key: tls_key.map(PathBuf::from),
    }
}

#[test]
fn public_plaintext_binding_is_rejected() {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443);
    assert!(config(bind, None, None, false).validate().is_err());
}

#[test]
fn built_in_tls_allows_public_binding() {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443);
    assert!(
        config(bind, Some("server.pem"), Some("server-key.pem"), false)
            .validate()
            .is_ok()
    );
}

#[test]
fn partial_built_in_tls_configuration_is_rejected() {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443);
    assert!(
        config(bind, Some("server.pem"), None, false)
            .validate()
            .is_err()
    );
    assert!(
        config(bind, None, Some("server-key.pem"), false)
            .validate()
            .is_err()
    );
}

#[test]
fn built_in_tls_and_proxy_header_trust_cannot_be_combined() {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443);
    assert!(
        config(bind, Some("server.pem"), Some("server-key.pem"), true)
            .validate()
            .is_err()
    );
}
