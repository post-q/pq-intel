//! OpenSSL legacy transport (feature `openssl-tls`): TLS 1.0/1.1 and
//! `DEFAULT@SECLEVEL=0` for servers rustls cannot reach — the
//! `openssl s_client` bar, verification off: the tools probe untrusted
//! infrastructure and must record what is served, not reject it.
//!
//! Produces the same [`TlsSessionFacts`] as every connector (see
//! [`super::tls_connector`]), so apps keep one observation definition and
//! put the fallback policy at their strategy layer. No PQ key exchange
//! exists below TLS 1.3, so `kex_group` is always empty here; ALPN is not
//! negotiated.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::tls_connector::TlsSessionFacts;

/// Direct TLS over a new connection to `ip:port`; `host` is the SNI name.
pub fn connect(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    timeout: Duration,
) -> Result<TlsSessionFacts, String> {
    let addr = match ip {
        Some(ip) => SocketAddr::from((ip, port)),
        None => return Err("host unresolved".to_string()),
    };

    let stream =
        std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("tcp: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("tcp: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("tcp: {e}"))?;
    connect_over_stream(host, stream)
}

/// TLS over an already-connected stream, e.g. one an app upgraded via a
/// plaintext protocol handshake (STARTTLS) first. Read/write timeouts are
/// the caller's to set on the stream.
pub fn connect_over_stream(host: &str, stream: std::net::TcpStream) -> Result<TlsSessionFacts, String> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .map_err(|e| e.to_string())?;
    builder
        .set_cipher_list("DEFAULT@SECLEVEL=0")
        .map_err(|e| e.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let mut config = connector.configure().map_err(|e| e.to_string())?;
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(false);

    let tls = config.connect(host, stream).map_err(|e| format!("tls: {e}"))?;
    let ssl = tls.ssl();

    // Client-side peer chain includes the leaf.
    let chain: Vec<Vec<u8>> = ssl
        .peer_cert_chain()
        .map(|chain| chain.iter().filter_map(|cert| cert.to_der().ok()).collect())
        .unwrap_or_default();

    Ok(TlsSessionFacts {
        protocol_version: ssl.version_str().to_string(),
        cipher_suite: ssl
            .current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_default(),
        kex_group: String::new(),
        alpn_negotiated: None,
        sni_used: host.to_string(),
        chain,
    })
}
