//! Model mapping: core certwatch rows → pq-map's graph model. The
//! certwatch semantics (timestamp repair, name handling, RFC 6125
//! coverage, serial normalization, jq-epoch validity) live in
//! `pq_core::evidence::collectors::ct`; this module only shapes the
//! presentation model (`crate::model::Certificate`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::model::{CertRef, Certificate};

use pq_core::evidence::collectors::ct::{
    CtShRow, coverage, ctdate, currently_valid, future_valid, names, serial_norm,
};
use pq_core::evidence::collectors::ctdb::DbRow;
use pq_core::x509::cert_signature_from_db;

pub fn certificates(rows: &[CtShRow], now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    let mut certs: BTreeMap<String, Certificate> = BTreeMap::new();
    for row in rows {
        let nb = row.not_before.as_deref().and_then(ctdate);
        let na = row.not_after.as_deref().and_then(ctdate);
        let valid = currently_valid(nb, na, now);
        let future = future_valid(nb, now);
        if !valid && !future {
            continue;
        }
        let Some(serial_raw) = &row.serial_number else {
            continue;
        };
        let serial = serial_norm(serial_raw);
        if serial == "0" {
            continue;
        }
        let identities = row.name_value.as_deref().map(names).unwrap_or_default();
        let entry = certs.entry(serial.clone()).or_insert_with(|| Certificate {
            serial: serial.clone(),
            in_ct: true,
            served_live: false,
            currently_valid: valid,
            ct_ids: Vec::new(),
            common_name: row.common_name.clone(),
            identities: identities.clone(),
            not_before: nb,
            not_after: na,
            pubkey_alg: None,
            sig_alg: None,
            issuer: None,
            key_algorithm: None,
            key_size: None,
            sig_key_algorithm: None,
            sig_hash_algorithm: None,
            cert_signature: None,
            chain: Vec::new(),
        });
        if let Some(id) = row.id {
            let id = id as u64;
            if !entry.ct_ids.contains(&id) {
                entry.ct_ids.push(id);
            }
        }
        if valid {
            entry.currently_valid = true;
        }
        if entry.common_name.is_none() {
            entry.common_name = row.common_name.clone();
        }
    }
    for cert in certs.values_mut() {
        cert.ct_ids.sort_unstable();
        cert.ct_ids.dedup();
    }
    certs
}

pub fn certificates_from_db(rows: &[DbRow], now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    let mut certs: BTreeMap<String, Certificate> = BTreeMap::new();
    for row in rows {
        let nb = row.not_before.as_deref().and_then(ctdate);
        let na = row.not_after.as_deref().and_then(ctdate);
        let valid = currently_valid(nb, na, now);
        let future = future_valid(nb, now);
        if !valid && !future {
            continue;
        }
        let serial = serial_norm(&row.serial);
        if serial == "0" {
            continue;
        }
        let Some(name) = row
            .dns_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let name = name.to_lowercase();
        let cert_signature = cert_signature_from_db(
            row.key_algorithm.as_deref(),
            row.key_size,
            row.sig_key_algorithm.as_deref(),
            row.sig_hash_algorithm.as_deref(),
        );
        let key_algorithm = row.key_algorithm.clone();
        let entry = certs.entry(serial.clone()).or_insert_with(|| Certificate {
            serial: serial.clone(),
            in_ct: true,
            served_live: false,
            currently_valid: valid,
            ct_ids: Vec::new(),
            common_name: row.common_name.clone(),
            identities: Vec::new(),
            not_before: nb,
            not_after: na,
            pubkey_alg: None,
            sig_alg: None,
            issuer: row.issuer_ca_name.clone(),
            key_algorithm,
            key_size: row.key_size,
            sig_key_algorithm: row.sig_key_algorithm.clone(),
            sig_hash_algorithm: row.sig_hash_algorithm.clone(),
            cert_signature,
            chain: Vec::new(),
        });
        if !entry.ct_ids.contains(&(row.cert_id as u64)) {
            entry.ct_ids.push(row.cert_id as u64);
        }
        if !entry.identities.contains(&name) {
            entry.identities.push(name);
        }
        if valid {
            entry.currently_valid = true;
        }
        if entry.common_name.is_none() {
            entry.common_name = row.common_name.clone();
        }
    }
    for cert in certs.values_mut() {
        cert.ct_ids.sort_unstable();
        cert.identities.sort();
    }
    certs
}

pub fn revive_certs(certs: Vec<Certificate>, now: DateTime<Utc>) -> BTreeMap<String, Certificate> {
    certs
        .into_iter()
        .map(|mut c| {
            c.currently_valid = currently_valid(c.not_before, c.not_after, now);
            c
        })
        .map(|c| (c.serial.clone(), c))
        .collect()
}

pub fn cert_refs(certs: &BTreeMap<String, Certificate>, host: &str) -> Vec<CertRef> {
    let mut refs = Vec::new();
    for cert in certs.values().filter(|c| c.currently_valid) {
        if let Some(kind) = coverage(&cert.identities, host) {
            refs.push(CertRef {
                serial: cert.serial.clone(),
                kind,
            });
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::evidence::collectors::ct::MatchKind;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn r(
        id: u64,
        common_name: &str,
        name_value: &str,
        not_before: &str,
        not_after: &str,
        serial: &str,
    ) -> CtShRow {
        CtShRow {
            id: Some(id as i64),
            common_name: Some(common_name.into()),
            name_value: Some(name_value.into()),
            not_before: Some(not_before.into()),
            not_after: Some(not_after.into()),
            serial_number: Some(serial.into()),
            ..CtShRow {
                id: None,
                issuer_ca_id: None,
                issuer_name: None,
                name_value: None,
                common_name: None,
                not_before: None,
                not_after: None,
                serial_number: None,
                min_entry_timestamp: None,
                cert: None,
            }
        }
    }

    #[test]
    fn certificates_dedups_by_serial_and_collects_ids() {
        let rows = vec![
            r(2, "www.example.com", "www.example.com\nexample.com", "2026-01-01T00:00:00", "2027-01-01T00:00:00", "0AA11"),
            r(1, "www.example.com", "www.example.com", "2026-01-01T00:00:00", "2027-01-01T00:00:00", "AA11"),
            r(3, "future", "future.example.com", "2027-06-01T00:00:00", "2028-01-01T00:00:00", "BB22"),
            r(4, "expired", "expired.example.com", "2020-01-01T00:00:00", "2021-01-01T00:00:00", "CC33"),
        ];
        let now = utc("2026-09-21T12:00:00Z");
        let certs = certificates(&rows, now);
        assert_eq!(certs.len(), 2);
        let aa = &certs["aa11"];
        assert_eq!(aa.ct_ids, vec![1, 2]);
        assert!(aa.currently_valid);
        assert_eq!(aa.identities, vec!["example.com", "www.example.com"]);
        let bb = &certs["bb22"];
        assert!(!bb.currently_valid);
    }

    #[test]
    fn certificates_from_db_group_by_serial_and_name_facts() {
        let rows = vec![
            DbRow {
                cert_id: 27387939567,
                serial: "069ee4d86e61f5bc610cd369ea2e8784".into(),
                dns_name: Some("3dsecure.example.com".into()),
                common_name: Some("3dsecure.example.com".into()),
                not_before: Some("2026-05-27 00:00:00".into()),
                not_after: Some("2026-12-11 23:59:59".into()),
                key_algorithm: Some("RSA".into()),
                key_size: Some(2048),
                sig_key_algorithm: Some("RSA".into()),
                sig_hash_algorithm: Some("SHA-256".into()),
                issuer_ca_name: Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1".into()),
            },
            DbRow {
                cert_id: 26679999700,
                serial: "069ee4d86e61f5bc610cd369ea2e8784".into(),
                dns_name: Some("www.example.com".into()),
                common_name: Some("3dsecure.example.com".into()),
                not_before: Some("2026-05-27 00:00:00".into()),
                not_after: Some("2026-12-11 23:59:59".into()),
                key_algorithm: Some("RSA".into()),
                key_size: Some(2048),
                sig_key_algorithm: Some("RSA".into()),
                sig_hash_algorithm: Some("SHA-256".into()),
                issuer_ca_name: Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1".into()),
            },
            DbRow {
                cert_id: 28833473386,
                serial: "0e0058034625f04166936598b0748415".into(),
                dns_name: Some("*.api.example.com".into()),
                common_name: Some("*.api.example.com".into()),
                not_before: Some("2026-08-19 00:00:00".into()),
                not_after: Some("2027-03-05 23:59:59".into()),
                key_algorithm: Some("EC".into()),
                key_size: Some(384),
                sig_key_algorithm: Some("ECDSA".into()),
                sig_hash_algorithm: Some("SHA-384".into()),
                issuer_ca_name: Some("CN=Test EC CA".into()),
            },
            DbRow {
                cert_id: 1,
                serial: "0deadbeef".into(),
                dns_name: Some("gone.example.com".into()),
                common_name: None,
                not_before: Some("2020-01-01 00:00:00".into()),
                not_after: Some("2021-01-01 00:00:00".into()),
                key_algorithm: None,
                key_size: None,
                sig_key_algorithm: None,
                sig_hash_algorithm: None,
                issuer_ca_name: None,
            },
        ];
        let now = utc("2026-09-21T12:00:00Z");
        let certs = certificates_from_db(&rows, now);
        assert_eq!(certs.len(), 2, "expired row dropped, duplicates merged");

        let rsa = &certs["69ee4d86e61f5bc610cd369ea2e8784"];
        assert_eq!(rsa.ct_ids, vec![26679999700, 27387939567]);
        assert_eq!(
            rsa.identities,
            vec!["3dsecure.example.com", "www.example.com"]
        );
        assert!(rsa.currently_valid);
        assert_eq!(rsa.cert_signature.as_deref(), Some("RSA-SHA256"));
        assert_eq!(rsa.key_size, Some(2048));
        assert_eq!(
            rsa.issuer.as_deref(),
            Some("C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1")
        );

        let ec = &certs["e0058034625f04166936598b0748415"];
        assert_eq!(ec.cert_signature.as_deref(), Some("ECDSA-P384"));
    }

    #[test]
    fn cert_refs_exact_and_wildcard() {
        let now = utc("2026-09-21T12:00:00Z");
        let rows = vec![
            r(1, "www.example.com", "www.example.com", "2026-01-01T00:00:00", "2027-01-01T00:00:00", "AA11"),
            r(2, "*.example.com", "*.example.com", "2026-01-01T00:00:00", "2027-01-01T00:00:00", "BB22"),
        ];
        let certs = certificates(&rows, now);
        let refs = cert_refs(&certs, "vpn.example.com");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].serial, "bb22");
        assert_eq!(refs[0].kind, MatchKind::Wildcard);
        let refs = cert_refs(&certs, "www.example.com");
        assert_eq!(refs.len(), 2);
    }
}
