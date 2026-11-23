//! The TLS connector seam. The collector (see [`super::tls`]) is one
//! definition of a TLS observation; connectors provide the transport.
//!
//! Production: [`RustlsConnector`] (rustls + aws-lc-rs, post-quantum kex
//! preferred, certificate verification disabled — the tools probe untrusted
//! infrastructure and must record what is served, not reject it). Apps may
//! add connectors for capabilities rustls lacks (pq-map's openssl fallback
//! for TLS 1.0/1.1 implements the same trait); every connector feeds the
//! same observation definition.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Connect target with the parameters that affect the response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsEndpoint {
    /// Hostname or IP literal.
    pub host: String,
    pub port: u16,
    /// SNI name; defaults to `host`.
    pub sni: Option<String>,
    /// ALPN protocol list, in preference order.
    pub alpn: Vec<String>,
    /// Identity of the client configuration (protocol versions, kex
    /// preference). Part of the collection key.
    pub client_config: String,
}

/// What the served connection negotiated — the raw material of a TLS
/// observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSessionFacts {
    /// "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "other".
    pub protocol_version: String,
    /// Negotiated cipher suite, e.g. `TLS13_AES_128_GCM_SHA256`.
    pub cipher_suite: String,
    /// Negotiated key exchange group, e.g. `X25519MLKEM768`.
    pub kex_group: String,
    /// Negotiated ALPN protocol, if any.
    pub alpn_negotiated: Option<String>,
    /// SNI actually used.
    pub sni_used: String,
    /// Served chain: leaf first, DER-encoded.
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsConnectError {
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("dns resolution failed: {0}")]
    Dns(String),
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("handshake failed: {message} (alert: {alert:?})")]
    Handshake {
        alert: Option<String>,
        message: String,
    },
}

/// Blocking TLS connector seam.
pub trait TlsConnector: Send + Sync {
    fn connect(&self, endpoint: &TlsEndpoint) -> Result<TlsSessionFacts, TlsConnectError>;
}

/// Verifier that accepts everything and captures the served chain. The
/// pq-intel tools probe untrusted infrastructure; verification failure is
/// evidence, not an error.
#[derive(Debug)]
pub struct ChainCapturingVerifier {
    chain: std::sync::Mutex<Vec<Vec<u8>>>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ChainCapturingVerifier {
    pub fn new() -> Self {
        Self {
            chain: std::sync::Mutex::new(vec![]),
            crypto_provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl Default for ChainCapturingVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for ChainCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = self.chain.lock().unwrap();
        *chain = std::iter::once(end_entity.as_ref().to_vec())
            .chain(intermediates.iter().map(|c| c.as_ref().to_vec()))
            .collect();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS session whose live stream continues to be usable (SMTP STARTTLS).
/// The handshake is complete; `facts` are final.
pub struct TlsUpgradedSession {
    pub facts: TlsSessionFacts,
    pub stream: rustls::StreamOwned<ClientConnection, TcpStream>,
}

/// Production connector: rustls with PQ-preferred defaults
/// (`prefer-post-quantum`), no verification, chain capture.
pub struct RustlsConnector {
    pub timeout: Duration,
}

impl RustlsConnector {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn client_config(
        &self,
        alpn: &[String],
        verifier: &Arc<ChainCapturingVerifier>,
    ) -> ClientConfig {
        // Pin the provider explicitly: ureq enables rustls's `ring` feature
        // while this crate enables `aws_lc_rs`, so BOTH provider features are
        // on and `ClientConfig::builder()`'s process-level auto-detection
        // panics (only visible on real network runs — tests use canned
        // connectors). aws-lc-rs is the PQ-capable provider this crate
        // prefers (`prefer-post-quantum` orders its groups PQ-first).
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("aws-lc-rs supports TLS 1.2/1.3")
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        config
    }

    /// Complete the handshake on an ALREADY-CONNECTED socket (SMTP
    /// STARTTLS / implicit TLS on a dialed port) and return both the facts
    /// and the live stream. Same handshake implementation as `connect`.
    pub fn upgrade(
        &self,
        sni: &str,
        alpn: &[String],
        sock: TcpStream,
    ) -> Result<TlsUpgradedSession, TlsConnectError> {
        let verifier = Arc::new(ChainCapturingVerifier::new());
        let config = self.client_config(alpn, &verifier);
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| TlsConnectError::Dns(format!("bad SNI name `{sni}`: {e}")))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| TlsConnectError::Connection(e.to_string()))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| TlsConnectError::Connection(e.to_string()))?;
        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| {
            TlsConnectError::Handshake {
                alert: None,
                message: e.to_string(),
            }
        })?;
        let mut stream = rustls::StreamOwned::new(conn, sock);
        let io_err = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                TlsConnectError::Timeout(self.timeout)
            }
            _ => TlsConnectError::Connection(e.to_string()),
        };
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).map_err(io_err)?;
        }
        let facts = facts_from_conn(&stream.conn, &mut verifier.chain.lock().unwrap(), sni);
        Ok(TlsUpgradedSession { facts, stream })
    }
}

fn facts_from_conn(
    conn: &ClientConnection,
    chain: &mut Vec<Vec<u8>>,
    sni: &str,
) -> TlsSessionFacts {
    let protocol_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLS 1.0",
        Some(_) => "other",
        None => "<none>",
    }
    .to_string();
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "<none>".to_string());
    let kex_group = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_else(|| "<none>".to_string());
    let alpn_negotiated = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    let chain = std::mem::take(chain);
    TlsSessionFacts {
        protocol_version,
        cipher_suite,
        kex_group,
        alpn_negotiated,
        sni_used: sni.to_string(),
        chain,
    }
}

impl TlsConnector for RustlsConnector {
    fn connect(&self, endpoint: &TlsEndpoint) -> Result<TlsSessionFacts, TlsConnectError> {
        let verifier = Arc::new(ChainCapturingVerifier::new());
        let config = self.client_config(&endpoint.alpn, &verifier);

        let sni = endpoint
            .sni
            .clone()
            .unwrap_or_else(|| endpoint.host.clone());
        let server_name = ServerName::try_from(sni.clone())
            .map_err(|e| TlsConnectError::Dns(format!("bad SNI name `{sni}`: {e}")))?;

        let addr_iter = (endpoint.host.as_str(), endpoint.port)
            .to_socket_addrs()
            .map_err(|e| TlsConnectError::Dns(e.to_string()))?;
        let mut last_err = None;
        let mut sock = None;
        for addr in addr_iter {
            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut sock = sock.ok_or_else(|| match last_err {
            Some(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                TlsConnectError::Timeout(self.timeout)
            }
            Some(e) => TlsConnectError::Connection(e.to_string()),
            None => TlsConnectError::Connection("no addresses".into()),
        })?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| TlsConnectError::Connection(e.to_string()))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| TlsConnectError::Connection(e.to_string()))?;

        let mut conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| {
            TlsConnectError::Handshake {
                alert: None,
                message: e.to_string(),
            }
        })?;

        let io_err = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                TlsConnectError::Timeout(self.timeout)
            }
            _ => TlsConnectError::Connection(e.to_string()),
        };
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(io_err)?;
        }

        let mut chain = std::mem::take(&mut *verifier.chain.lock().unwrap());
        Ok(facts_from_conn(&conn, &mut chain, &sni))
    }
}
