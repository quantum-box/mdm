//! Native TLS and HTTP/1.1+HTTP/2 serving for the standalone binary.

use crate::{
    gateway::GatewayKey,
    http::{App, AuthenticatedTlsPeer, router_with_gateway},
    storage,
};
use anyhow::{Context, Result, bail};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
    service::TowerToHyperService,
};
use openssl::{
    asn1::Asn1Time,
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509Ref},
};
use std::{
    fs, future::Future, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, pin::Pin,
    sync::Arc, time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_openssl::SslStream;

const MAX_CONNECTIONS: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP1_BUFFER_SIZE: usize = 32 * 1024;
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Builds the server TLS context used by [`serve`].
pub fn build_acceptor(
    certificate_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<SslAcceptor> {
    validate_private_key_mode(key_path)?;
    let certificate_pem = fs::read(certificate_path)
        .with_context(|| format!("read TLS certificate {}", certificate_path.display()))?;
    let certificates =
        X509::stack_from_pem(&certificate_pem).context("parse TLS server certificate chain")?;
    let leaf = certificates
        .first()
        .context("TLS server certificate chain is empty")?;
    ensure_valid_now(leaf).context("TLS server certificate is not currently valid")?;
    let key_pem = fs::read(key_path)
        .with_context(|| format!("read TLS private key {}", key_path.display()))?;
    let key = PKey::private_key_from_pem(&key_pem).context("parse TLS private key")?;
    if !leaf
        .public_key()
        .context("read TLS server public key")?
        .public_eq(&key)
    {
        bail!("TLS server certificate and private key do not match");
    }

    let ca_pem = fs::read(client_ca_path)
        .with_context(|| format!("read TLS client CA {}", client_ca_path.display()))?;
    let ca_certificates = X509::stack_from_pem(&ca_pem).context("parse TLS client CA")?;
    if ca_certificates.len() != 1 {
        bail!("TLS client CA file must contain exactly one certificate");
    }
    let client_ca = ca_certificates.first().context("TLS client CA is empty")?;
    ensure_valid_now(client_ca).context("TLS client CA is not currently valid")?;

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
        .context("create TLS server context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .context("set TLS minimum version")?;
    builder
        .set_certificate_chain_file(certificate_path)
        .context("load TLS server certificate chain")?;
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .context("load TLS server private key")?;
    builder
        .check_private_key()
        .context("check TLS server private key")?;
    // PEER verifies a client certificate when one is supplied, while omitting
    // FAIL_IF_NO_PEER_CERT keeps bootstrap and administrative routes usable.
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_verify_depth(2);
    builder
        .set_ca_file(client_ca_path)
        .context("trust TLS client CA")?;
    builder
        .add_client_ca(client_ca)
        .context("advertise TLS client CA")?;
    builder.set_alpn_select_callback(|_, client_protocols| {
        openssl::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_protocols)
            .ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

/// Serves the application over native TLS with bounded connections and a
/// graceful shutdown deadline.
pub async fn serve(
    listener: TcpListener,
    app: App,
    certificate_path: &Path,
    key_path: &Path,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    serve_with_gateway(listener, app, certificate_path, key_path, None, shutdown).await
}

/// Serves the application over native TLS and, when configured, the signed
/// gateway envelope.  The gateway layer is applied inside each TLS connection
/// so its authenticated peer extension supersedes the origin TLS peer.
pub async fn serve_with_gateway(
    listener: TcpListener,
    app: App,
    certificate_path: &Path,
    key_path: &Path,
    gateway_key: Option<GatewayKey>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    let acceptor = Arc::new(build_acceptor(
        certificate_path,
        key_path,
        &app.config.ca_cert,
    )?);
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(_)) = completed {
                    // Connection failures are isolated to their task and do
                    // not reveal certificate or request details in logs.
                }
            }
            accepted = listener.accept() => {
                let (stream, peer_address): (TcpStream, SocketAddr) = accepted
                    .context("accept TLS connection")?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(stream);
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                let gateway_key = gateway_key.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, peer_address, acceptor, app, gateway_key).await;
                });
            }
        }
    }

    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain)
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    acceptor: Arc<SslAcceptor>,
    app: App,
    gateway_key: Option<GatewayKey>,
) {
    let ssl = match Ssl::new(acceptor.context()) {
        Ok(ssl) => ssl,
        Err(_) => return,
    };
    let mut stream = match SslStream::new(ssl, stream) {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let handshake =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, Pin::new(&mut stream).accept()).await;
    if !matches!(handshake, Ok(Ok(()))) {
        return;
    }

    let peer = match stream.ssl().peer_certificate() {
        None => (None, 0),
        Some(certificate) => {
            let pem = match certificate.to_pem() {
                Ok(pem) => pem,
                Err(_) => return,
            };
            let fingerprint = match app.identity.verify_client_certificate(&pem) {
                Ok(fingerprint) => fingerprint,
                Err(_) => return,
            };
            let now = storage::now();
            let now_asn1 = match Asn1Time::from_unix(now as _) {
                Ok(value) => value,
                Err(_) => return,
            };
            let remaining = match now_asn1.diff(certificate.not_after()) {
                Ok(value) if value.days >= 0 && value.secs >= 0 => i64::from(value.days)
                    .checked_mul(86_400)
                    .and_then(|days| days.checked_add(i64::from(value.secs))),
                _ => None,
            };
            let expires_at = match remaining.and_then(|value| now.checked_add(value)) {
                Some(value) if value > now => value,
                _ => return,
            };
            (Some(fingerprint), expires_at)
        }
    };
    let application = router_with_gateway(
        app,
        gateway_key,
        Some((AuthenticatedTlsPeer(peer.0, peer.1), peer_address)),
    );
    let service = TowerToHyperService::new(application);
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .max_buf_size(HTTP1_BUFFER_SIZE)
        .header_read_timeout(HTTP_HEADER_TIMEOUT)
        .timer(TokioTimer::new());
    builder
        .http2()
        .max_concurrent_streams(32)
        .timer(TokioTimer::new());
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await;
}

fn validate_private_key_mode(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("stat TLS private key {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        bail!("TLS private key must have file mode 0600");
    }
    Ok(())
}

fn ensure_valid_now(certificate: &X509Ref) -> Result<()> {
    let now = Asn1Time::days_from_now(0).context("get current certificate time")?;
    if certificate
        .not_before()
        .compare(&now)
        .context("compare certificate notBefore")?
        == std::cmp::Ordering::Greater
    {
        bail!("certificate is not yet valid");
    }
    if certificate
        .not_after()
        .compare(&now)
        .context("compare certificate notAfter")?
        != std::cmp::Ordering::Greater
    {
        bail!("certificate has expired");
    }
    Ok(())
}
