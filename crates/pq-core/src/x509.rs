//! X.509 and TLS naming semantics, shared by every tool that touches
//! certificates: OID tables, algorithm classification, canonical signature
//! and key names, cipher-suite naming. Pure string/integer logic - no
//! model types, no I/O. Consumers: the CT collector's certwatch rows,
//! pq-map's live-probe and model mapping, pq-pulse's TLS facts.

use x509_parser::der_parser::oid::Oid;

const PUBKEY_OIDS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.113549.1.1.10", "rsassaPss"),
    ("1.2.840.10045.2.1", "id-ecPublicKey"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
];

const SIG_OIDS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "rsassaPss"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.114", "Ed448"),
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
];

const EC_CURVE_OIDS: &[(&str, &str)] = &[
    ("1.2.840.10045.3.1.7", "P256"),
    ("1.3.132.0.34", "P384"),
    ("1.3.132.0.35", "P521"),
];

/// OID → table name; unknown OIDs render as their dotted string.
pub fn oid_name(oid: &Oid, table: &[(&str, &str)]) -> String {
    let dotted = oid.to_id_string();
    table
        .iter()
        .find(|(k, _)| *k == dotted)
        .map(|(_, v)| v.to_string())
        .unwrap_or(dotted)
}

/// Public-key algorithm OID → name (`rsaEncryption`, `id-ecPublicKey`, ...).
pub fn pubkey_alg_from_oid(oid: &Oid) -> String {
    oid_name(oid, PUBKEY_OIDS)
}

/// Signature algorithm OID → name (`sha256WithRSAEncryption`, ...).
pub fn sig_alg_from_oid(oid: &Oid) -> String {
    oid_name(oid, SIG_OIDS)
}

/// EC curve OID → NIST curve name (`P256`, ...); non-EC OIDs are None.
pub fn curve_from_oid(oid: &Oid) -> Option<&'static str> {
    let dotted = oid.to_id_string();
    EC_CURVE_OIDS
        .iter()
        .find(|(k, _)| *k == dotted)
        .map(|(_, v)| *v)
}

/// Signature algorithm name of a DER certificate (shared: leaf + chain scan).
pub fn sig_alg_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(oid_name(&cert.signature_algorithm.algorithm, SIG_OIDS))
}

/// RFC 2253 rendering (most specific RDN first), like `openssl -nameopt RFC2253`.
pub fn issuer_rfc2253(name: &x509_parser::x509::X509Name) -> String {
    const RDN_SHORT_NAMES: &[(&str, &str)] = &[
        ("2.5.4.3", "CN"),
        ("2.5.4.6", "C"),
        ("2.5.4.7", "L"),
        ("2.5.4.8", "ST"),
        ("2.5.4.10", "O"),
        ("2.5.4.11", "OU"),
        ("2.5.4.5", "serialNumber"),
        ("0.9.2342.19200300.100.1.25", "DC"),
        ("1.2.840.113549.1.9.1", "emailAddress"),
    ];
    let parts: Vec<String> = name
        .iter_rdn()
        .flat_map(|rdn| rdn.iter())
        .map(|atv| {
            let dotted = atv.attr_type().to_id_string();
            let key = RDN_SHORT_NAMES
                .iter()
                .find(|(k, _)| *k == dotted)
                .map(|(_, v)| v.to_string())
                .unwrap_or(dotted);
            let value = atv
                .as_str()
                .map(std::borrow::ToOwned::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(atv.as_slice()).into_owned());
            format!("{key}={value}")
        })
        .collect();
    parts.into_iter().rev().collect::<Vec<_>>().join(",")
}

/// "SHA-256" → "SHA256"; trims and drops dashes, uppercased.
fn hash_norm(raw: &str) -> String {
    raw.trim().to_ascii_uppercase().replace('-', "")
}

/// Algorithm string (OID name, LN, or shorthand) → canonical class.
pub fn alg_class_of(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("ed25519") {
        "Ed25519".to_string()
    } else if lower.contains("ed448") {
        "Ed448".to_string()
    } else if lower.starts_with("ml-dsa") || lower.contains("mldsa") {
        raw.trim().to_string()
    } else if lower.contains("ecdsa") || lower.contains("ecpublickey") || lower == "ec" {
        "ECDSA".to_string()
    } else if lower.contains("rsa") {
        "RSA".to_string()
    } else {
        raw.trim().to_string()
    }
}

/// EC key size → NIST curve name; non-EC sizes are None.
pub fn curve_from_key_size(size: i64) -> Option<&'static str> {
    match size {
        256 => Some("P256"),
        384 => Some("P384"),
        521 => Some("P521"),
        _ => None,
    }
}

/// Canonical public-key name: `RSA-2048`, `EC-256`, `Ed25519`.
pub fn cert_key_name(
    alg: Option<&str>,
    key_size: Option<i64>,
    curve: Option<&str>,
) -> Option<String> {
    let class = alg_class_of(alg?);
    if class == "ECDSA" {
        let bits = key_size.or_else(|| {
            curve.and_then(|c| c.trim().trim_start_matches(['P', 'p', '-']).parse().ok())
        });
        return Some(match bits {
            Some(b) => format!("EC-{b}"),
            None => "EC".to_string(),
        });
    }
    Some(match key_size {
        Some(b) => format!("{class}-{b}"),
        None => class,
    })
}

/// Canonical signature name: `RSA-SHA256`, `ECDSA-P384`, `ML-DSA-65`.
pub fn cert_signature_name(class: &str, hash: Option<&str>, curve: Option<&str>) -> Option<String> {
    let class = alg_class_of(class);
    match class.as_str() {
        "RSA" => Some(match hash.map(hash_norm) {
            Some(h) => format!("RSA-{h}"),
            None => "RSA".to_string(),
        }),
        "ECDSA" => Some(match curve {
            Some(c) => format!("ECDSA-{c}"),
            None => "ECDSA".to_string(),
        }),
        other => Some(other.to_string()),
    }
}

/// Canonical signature name from certwatch DB columns (key/sig algorithm
/// + key size; EC curve derived from the size).
pub fn cert_signature_from_db(
    key_algorithm: Option<&str>,
    key_size: Option<i64>,
    sig_key_algorithm: Option<&str>,
    sig_hash_algorithm: Option<&str>,
) -> Option<String> {
    let class = sig_key_algorithm.or(key_algorithm)?;
    let curve = if alg_class_of(class) == "ECDSA" {
        key_size.and_then(curve_from_key_size)
    } else {
        None
    };
    cert_signature_name(class, sig_hash_algorithm, curve)
}

/// "sha256WithRSAEncryption" → "SHA256", "SHA-384" → "SHA384".
fn hash_from_sig(sig_lower: &str) -> Option<&'static str> {
    const HASHES: [(&str, &str); 5] = [
        ("sha512", "SHA512"),
        ("sha384", "SHA384"),
        ("sha256", "SHA256"),
        ("sha1", "SHA1"),
        ("md5", "MD5"),
    ];
    HASHES
        .iter()
        .find(|(needle, _)| sig_lower.contains(needle))
        .map(|(_, name)| *name)
}

/// Canonical signature name from a live probe's peer-certificate fields.
pub fn live_cert_signature(
    pubkey_alg: Option<&str>,
    sig_alg: Option<&str>,
    curve: Option<String>,
) -> Option<String> {
    let sig = sig_alg?;
    let lower = sig.to_ascii_lowercase();
    let (class, hash): (String, Option<&str>) = if lower.contains("ecdsa") {
        ("ECDSA".to_string(), hash_from_sig(&lower))
    } else if lower.contains("ed25519") {
        ("Ed25519".to_string(), None)
    } else if lower.contains("ed448") {
        ("Ed448".to_string(), None)
    } else if lower.contains("rsa") {
        ("RSA".to_string(), hash_from_sig(&lower))
    } else if let Some(pubkey) = pubkey_alg {
        (alg_class_of(pubkey), hash_from_sig(&lower))
    } else {
        (sig.to_string(), None)
    };
    cert_signature_name(&class, hash, curve.as_deref())
}

/// TLS cipher suite → canonical symmetric name: `AES128-GCM`, `AES256-CBC`,
/// `CHACHA20-POLY1305`; unrecognized suites are None.
pub fn symmetric_name(cipher: &str) -> Option<String> {
    let upper = cipher.to_ascii_uppercase();
    if upper.contains("CHACHA20") {
        return Some("CHACHA20-POLY1305".to_string());
    }
    let bits = if upper.contains("AES_128") {
        "AES128"
    } else if upper.contains("AES_256") {
        "AES256"
    } else {
        return None;
    };
    let mode = if upper.contains("GCM") {
        "GCM"
    } else if upper.contains("CBC") {
        "CBC"
    } else {
        return None;
    };
    Some(format!("{bits}-{mode}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_signature_names_are_canonical() {
        assert_eq!(cert_signature_name("rsaEncryption", Some("sha256"), None).as_deref(), Some("RSA-SHA256"));
        assert_eq!(cert_signature_name("id-ecPublicKey", Some("ecdsa-with-SHA384"), Some("P384")).as_deref(), Some("ECDSA-P384"));
        assert_eq!(cert_signature_name("Ed25519", None, None).as_deref(), Some("Ed25519"));
        assert_eq!(cert_signature_name("ML-DSA-65", None, None).as_deref(), Some("ML-DSA-65"));
        assert_eq!(cert_signature_name("1.2.3.4.5", None, None).as_deref(), Some("1.2.3.4.5"));
    }

    #[test]
    fn curve_from_key_size_maps_nist_curves() {
        assert_eq!(curve_from_key_size(256), Some("P256"));
        assert_eq!(curve_from_key_size(384), Some("P384"));
        assert_eq!(curve_from_key_size(521), Some("P521"));
        assert_eq!(curve_from_key_size(2048), None);
        assert_eq!(curve_from_key_size(512), None);
    }

    #[test]
    fn cert_key_names_are_canonical() {
        assert_eq!(cert_key_name(Some("RSA"), Some(2048), None), Some("RSA-2048".to_string()));
        assert_eq!(cert_key_name(Some("EC"), Some(256), None), Some("EC-256".to_string()));
        assert_eq!(cert_key_name(Some("EC"), Some(384), None), Some("EC-384".to_string()));
        assert_eq!(cert_key_name(Some("ECDSA"), None, Some("P256")), Some("EC-256".to_string()));
        assert_eq!(cert_key_name(Some("id-ecPublicKey"), None, Some("P521")), Some("EC-521".to_string()));
        assert_eq!(cert_key_name(Some("RSA"), None, None), Some("RSA".to_string()));
        assert_eq!(cert_key_name(Some("Ed25519"), None, None), Some("Ed25519".to_string()));
        assert_eq!(cert_key_name(None, None, None), None);
    }

    #[test]
    fn cert_signature_from_db_maps_ec_curve_from_key_size() {
        assert_eq!(
            cert_signature_from_db(Some("EC"), Some(256), Some("ECDSA"), Some("SHA-256")),
            Some("ECDSA-P256".to_string())
        );
        assert_eq!(cert_signature_from_db(None, None, None, None), None);
    }

    #[test]
    fn symmetric_names_from_suite_names() {
        assert_eq!(symmetric_name("TLS13_AES_256_GCM_SHA384").as_deref(), Some("AES256-GCM"));
        assert_eq!(symmetric_name("TLS_AES_128_GCM_SHA256").as_deref(), Some("AES128-GCM"));
        assert_eq!(symmetric_name("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").as_deref(), Some("AES128-GCM"));
        assert_eq!(symmetric_name("TLS13_CHACHA20_POLY1305_SHA256").as_deref(), Some("CHACHA20-POLY1305"));
        assert_eq!(symmetric_name("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384").as_deref(), Some("AES256-CBC"));
        assert_eq!(symmetric_name("TLS_UNKNOWN"), None);
    }
}
