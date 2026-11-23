//! Chain reconstruction over the certwatch DB. The connection session,
//! the snapshot query, and the row parsing live in
//! [`pq_core::evidence::collectors::ctdb`]; this module keeps only the
//! chain query — pq-map's visualization model — over the shared session.

use std::collections::BTreeMap;

use pq_core::evidence::collectors::ctdb::{CertwatchConfig, Session};

use crate::model::ChainEntry;

const CHAIN_SQL_TEMPLATE: &str = "
WITH RECURSIVE cert_chain AS (
    SELECT
        c.id                  AS certificate_id,
        c.issuer_ca_id,
        c.certificate,
        c.id                  AS leaf_id,
        0                     AS depth,
        ARRAY[c.id]::bigint[] AS path
    FROM certificate c
    WHERE c.id = ANY(ARRAY[{ids}]::bigint[])
      AND x509_notBefore(c.certificate) <= now()
      AND x509_notAfter(c.certificate) >= now()

    UNION ALL

    SELECT
        parent.id,
        parent.issuer_ca_id,
        parent.certificate,
        cc.leaf_id,
        cc.depth + 1,
        cc.path || parent.id
    FROM cert_chain cc

    JOIN LATERAL (
        SELECT c2.*
        FROM ca_certificate cac
        JOIN certificate c2
          ON c2.id = cac.certificate_id

        WHERE cac.ca_id = cc.issuer_ca_id
          AND x509_notBefore(c2.certificate) <= now()
          AND x509_notAfter(c2.certificate) >= now()
          AND NOT c2.id = ANY(cc.path)

          AND (
              x509_authorityKeyId(cc.certificate) IS NULL
              OR x509_subjectKeyIdentifier(c2.certificate)
                   = x509_authorityKeyId(cc.certificate)
          )

        ORDER BY
            CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM ca_certificate self_ca
                    WHERE self_ca.certificate_id = c2.id
                      AND self_ca.ca_id = c2.issuer_ca_id
                )
                THEN 0
                ELSE 1
            END,
            x509_notBefore(c2.certificate) DESC,
            x509_notAfter(c2.certificate) DESC,
            c2.id DESC

        LIMIT 1
    ) parent ON true

    WHERE cc.depth < 6

      AND NOT EXISTS (
          SELECT 1
          FROM ca_certificate self_ca
          WHERE self_ca.certificate_id = cc.certificate_id
            AND self_ca.ca_id = cc.issuer_ca_id
      )
)

SELECT
    cc.leaf_id,
    cc.depth,
    cc.certificate_id,
    cc.issuer_ca_id,

    x509_commonName(cc.certificate) AS common_name,

    encode(
        x509_subjectKeyIdentifier(cc.certificate),
        'hex'
    ) AS ski,

    encode(
        x509_authorityKeyId(cc.certificate),
        'hex'
    ) AS aki,

    x509_notBefore(cc.certificate)::text AS not_before,
    x509_notAfter(cc.certificate)::text AS not_after,

    x509_keyAlgorithm(cc.certificate) AS key_algorithm,
    x509_keySize(cc.certificate) AS key_size,

    x509_signatureKeyAlgorithm(cc.certificate)
        AS signature_key_algorithm,

    x509_signatureHashAlgorithm(cc.certificate)
        AS signature_hash_algorithm,

    issuer_ca.name AS issuer_ca_name

FROM cert_chain cc

LEFT JOIN ca issuer_ca
  ON issuer_ca.id = cc.issuer_ca_id

ORDER BY
    cc.leaf_id,
    cc.depth";

fn chain_sql(ct_ids: &[u64]) -> String {
    let ids = ct_ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    CHAIN_SQL_TEMPLATE.replace("{ids}", &ids)
}

/// The issuer→subject chains for the given certwatch ids, over this
/// session's connection (retries live in the core query helper).
pub async fn chain_rows(
    session: &mut Session,
    ct_ids: &[u64],
    cfg: &CertwatchConfig,
) -> Result<BTreeMap<u64, Vec<ChainEntry>>, String> {
    if ct_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let messages = session
        .query_with_retries(&chain_sql(ct_ids), cfg, "certificate chains")
        .await?;
    parse_chain_rows(&messages)
}

fn parse_chain_row(r: &tokio_postgres::SimpleQueryRow) -> Result<(u64, ChainEntry), String> {
    let leaf_id: u64 = r
        .get(0)
        .ok_or("missing leaf id")?
        .parse()
        .map_err(|_| "bad leaf id")?;
    let entry = ChainEntry {
        depth: r
            .get(1)
            .ok_or("missing depth")?
            .parse()
            .map_err(|_| "bad depth")?,
        certificate_id: r
            .get(2)
            .ok_or("missing cert id")?
            .parse()
            .map_err(|_| "bad cert id")?,
        common_name: r.get(4).map(str::to_string),
        ski: r.get(5).map(str::to_string),
        aki: r.get(6).map(str::to_string),
        not_before: r.get(7).and_then(pq_core::evidence::collectors::ct::ctdate),
        not_after: r.get(8).and_then(pq_core::evidence::collectors::ct::ctdate),
        key_algorithm: r.get(9).map(str::to_string),
        key_size: r.get(10).and_then(|v| v.parse().ok()),
        signature_key_algorithm: r.get(11).map(str::to_string),
        signature_hash_algorithm: r.get(12).map(str::to_string),
        issuer_ca_name: r.get(13).map(str::to_string),
    };
    Ok((leaf_id, entry))
}

fn parse_chain_rows(
    messages: &[tokio_postgres::SimpleQueryMessage],
) -> Result<BTreeMap<u64, Vec<ChainEntry>>, String> {
    let mut chains: BTreeMap<u64, Vec<ChainEntry>> = BTreeMap::new();
    for m in messages {
        if let tokio_postgres::SimpleQueryMessage::Row(r) = m {
            let (leaf_id, entry) = parse_chain_row(r)?;
            chains.entry(leaf_id).or_default().push(entry);
        }
    }
    Ok(chains)
}
