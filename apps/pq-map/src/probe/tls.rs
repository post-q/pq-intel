use std::net::IpAddr;
use std::time::Duration;

use crate::model::{Negotiated, ServedCert};

use pq_core::evidence::collectors::ct::serial_norm;
use pq_core::x509::{
    curve_from_oid, issuer_rfc2253, live_cert_signature, pubkey_alg_from_oid, sig_alg_from_der,
    sig_alg_from_oid,
};

use super::Failure;

/// Verifier that accepts everything: the probe inspects certificates like
/// `openssl s_client` does, it does not authenticate the endpoint.
/// Primary probe: the shared TLS collection (rustls with SNI against
/// host:port, MLKEM768 offered first via pq-core's default client config),
/// cached by the store with a one-day freshness window. `ip` is retained
/// for reporting only — the collection is keyed by the endpoint host, and
/// the connector resolves DNS itself.
pub async fn attempt(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    _cfg: &crate::config::Config,
    ev: &crate::store::MapEvidence,
) -> Result<(ServedCert, Negotiated), Failure> {
    let _ = ip;
    let owned = host.to_string();
    let ev = ev.clone();
    tokio::task::spawn_blocking(move || attempt_store(&ev, &owned, port))
        .await
        .map_err(|e| Failure::Unknown(format!("tls collection join: {e}")))?
}

/// How stale a reused TLS observation may be before a re-probe (seconds).
const TLS_STALE_SECS: u64 = 86_400;

fn attempt_store(
    ev: &crate::store::MapEvidence,
    host: &str,
    port: u16,
) -> Result<(ServedCert, Negotiated), Failure> {
    let req = pq_core::evidence::collectors::tls::TlsRequest::new(host, port)
        .map_err(|e| Failure::Unknown(e.to_string()))?;
    let collector = pq_core::evidence::collectors::tls::TlsCollector {
        connector: ev.tls.clone(),
    };
    let outcome = ev
        .scan
        .collect(
            &collector,
            req,
            pq_core::evidence::FreshnessRequirement::MaxAge(std::time::Duration::from_secs(
                TLS_STALE_SECS,
            )),
        )
        .map_err(|e| Failure::Unknown(e.to_string()))?;
    if let Some(f) = &outcome.failure {
        return Err(recorded_to_failure(f.clone()));
    }
    let observed = outcome
        .data
        .ok_or_else(|| Failure::Unknown("no TLS observation".into()))?;
    let facts = observed.session;
    if facts.chain.is_empty() {
        return Err(Failure::ClosedNoCert("no certificate served".to_string()));
    }
    served_and_negotiated(facts).map_err(Failure::Unknown)
}

/// Recorded store failure → probe failure. Connection-level errors map
/// to `Handshake` so the OpenSSL legacy fallback still gets its chance.
fn recorded_to_failure(f: pq_core::evidence::scan::RecordedFailure) -> Failure {
    use pq_core::evidence::observation::ObservationStatus as S;
    match f.status {
        S::Timeout => Failure::Timeout,
        S::NotFound => Failure::ClosedNoCert(
            f.native_status
                .unwrap_or_else(|| "no certificate served".into()),
        ),
        S::RateLimited => Failure::Handshake(format!(
            "rate limited{}",
            f.native_status
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        )),
        _ => Failure::Handshake(f.message.unwrap_or_else(|| "handshake failed".into())),
    }
}

/// Legacy fallback for servers rustls cannot reach (TLS 1.0/1.1, odd
/// ciphers): core's OpenSSL legacy transport (`SECLEVEL=0`, verification
/// off — the s_client bar), producing the same observation definition as
/// the rustls collection.
pub fn openssl_attempt(
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
    timeout: Duration,
) -> Result<(ServedCert, Negotiated), String> {
    let facts = pq_core::evidence::collectors::openssl_tls::connect(host, ip, port, timeout)?;
    served_and_negotiated(facts)
}

/// Shared mapping: the one TLS observation definition (core facts) →
/// probe model, for both the rustls collection and the OpenSSL fallback.
fn served_and_negotiated(
    facts: pq_core::evidence::collectors::tls_connector::TlsSessionFacts,
) -> Result<(ServedCert, Negotiated), String> {
    if facts.chain.is_empty() {
        return Err("connected, no certificate".to_string());
    }
    let chain_sigs: Vec<String> = facts
        .chain
        .iter()
        .filter_map(|der| sig_alg_from_der(der))
        .collect();
    let negotiated = Negotiated {
        tls_version: Some(facts.protocol_version.clone()),
        kx_group: Some(facts.kex_group.clone()).filter(|s| !s.is_empty()),
        cipher: Some(facts.cipher_suite.clone()).filter(|s| !s.is_empty()),
    };
    let leaf = facts.chain.first().cloned().unwrap_or_default();
    let served =
        served_cert_from_der(&leaf).ok_or_else(|| "certificate parse failed".to_string())?;
    Ok((served_with_chain_sigs(served, chain_sigs), negotiated))
}

/// Shared leaf-certificate extraction for both TLS stacks.
pub fn served_cert_from_der(der: &[u8]) -> Option<ServedCert> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;

    let serial = serial_norm(&hex_lower(cert.raw_serial()));
    let pubkey_alg = Some(pubkey_alg_from_oid(&cert.subject_pki.algorithm.algorithm));
    let sig_alg = Some(sig_alg_from_oid(&cert.signature_algorithm.algorithm));
    let pubkey_curve = cert
        .subject_pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .and_then(|o| curve_from_oid(&o))
        .map(str::to_string);
    let cert_signature = live_cert_signature(
        pubkey_alg.as_deref(),
        sig_alg.as_deref(),
        pubkey_curve.clone(),
    );
    let issuer = Some(issuer_rfc2253(&cert.issuer));

    let validity = cert.validity();
    let not_before = chrono::DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .map(|d| d.with_timezone(&chrono::Utc));
    let not_after = chrono::DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .map(|d| d.with_timezone(&chrono::Utc));

    let mut identities: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    identities.sort();
    identities.dedup();

    let common_name = cert
        .subject
        .iter_common_name()
        .next()
        .and_then(|atv| atv.as_str().ok())
        .map(str::to_string);

    Some(ServedCert {
        serial,
        common_name,
        identities,
        pubkey_alg,
        sig_alg,
        issuer,
        not_before,
        not_after,
        chain_sigs: Vec::new(),
        pubkey_curve,
        cert_signature,
    })
}

fn served_with_chain_sigs(mut served: ServedCert, chain_sigs: Vec<String>) -> ServedCert {
    served.chain_sigs = chain_sigs;
    served
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed RSA leaf generated with openssl for test purposes.
    const TEST_CERT_PEM: &str = include_str!("../../tests/data/test-leaf.pem");

    #[test]
    fn extracts_fields_from_der() {
        let pem = TEST_CERT_PEM.trim();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64_decode(&body);
        let served = served_cert_from_der(&der).expect("parse test certificate");

        assert!(!served.serial.is_empty());
        assert_eq!(served.common_name.as_deref(), Some("test.pq-map.invalid"));
        assert!(
            served
                .identities
                .contains(&"test.pq-map.invalid".to_string())
        );
        assert_eq!(served.pubkey_alg.as_deref(), Some("rsaEncryption"));
        assert!(
            served
                .sig_alg
                .as_deref()
                .is_some_and(|s| s.contains("sha256"))
        );
        assert_eq!(served.cert_signature.as_deref(), Some("RSA-SHA256"));
        assert!(served.not_before.is_some());
        assert!(served.not_after.is_some());
        assert!(served.pubkey_curve.is_none());
    }

    /// Self-signed EC P-256 leaf generated with openssl for test purposes.
    const TEST_EC_CERT_PEM: &str = include_str!("../../tests/data/test-ec-leaf.pem");

    #[test]
    fn extracts_ecdsa_curve_and_signature() {
        let pem = TEST_EC_CERT_PEM.trim();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64_decode(&body);
        let served = served_cert_from_der(&der).expect("parse test EC certificate");

        assert_eq!(served.pubkey_alg.as_deref(), Some("id-ecPublicKey"));
        assert_eq!(served.pubkey_curve.as_deref(), Some("P256"));
        assert_eq!(served.cert_signature.as_deref(), Some("ECDSA-P256"));
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for c in input.bytes() {
            let v = match TABLE.iter().position(|t| *t == c) {
                Some(v) => v as u32,
                None => continue,
            };
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xff) as u8);
            }
        }
        out
    }
}
