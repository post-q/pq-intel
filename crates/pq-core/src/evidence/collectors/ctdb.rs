//! The certwatch read path: PostgreSQL directly against crt.sh's public
//! certwatch database (port 5432, no TLS-terminated HTTP endpoint). This
//! is the primary CT transport — pq-map's implementation, promoted here
//! so every tool in the workspace shares one reader. The crt.sh JSON
//! API ([`super::ct`]) is the fallback for when the DB is unreachable.
//!
//! The snapshot query and the chain query (pq-map's) share one connection
//! per [`Session`]: connecting to crt.sh is expensive, and a failed or
//! timed-out query may still be running server-side, which poisons the
//! connection — it is hung up, and only the failed query re-runs on a
//! fresh one.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawArtifact, RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

/// Connection and retry knobs for the certwatch DB. Defaults mirror
/// pq-map's env defaults (crt.sh:5432, guest/certwatch, 10 attempts).
#[derive(Debug, Clone)]
pub struct CertwatchConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub dbname: String,
    pub connect_timeout: Duration,
    pub query_timeout: Duration,
    pub retries: u32,
    pub retry_delay: u64,
}

impl Default for CertwatchConfig {
    fn default() -> Self {
        Self {
            host: "crt.sh".into(),
            port: 5432,
            user: "guest".into(),
            dbname: "certwatch".into(),
            connect_timeout: Duration::from_secs(30),
            query_timeout: Duration::from_secs(120),
            retries: 10,
            retry_delay: 2,
        }
    }
}

/// One certwatch snapshot row (the DB column shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbRow {
    pub cert_id: i64,
    pub serial: String,
    pub dns_name: Option<String>,
    pub common_name: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_size: Option<i64>,
    pub sig_key_algorithm: Option<String>,
    pub sig_hash_algorithm: Option<String>,
    pub issuer_ca_name: Option<String>,
}

const CT_SQL_TEMPLATE: &str = "
WITH matching AS (
    SELECT c.id, c.issuer_ca_id, c.certificate
    FROM certificate c
    WHERE identities(c.certificate) @@ plainto_tsquery('certwatch', '{domain}')
      AND x509_notAfter(c.certificate) >= now()
)
SELECT
    m.id,
    encode(x509_serialnumber(m.certificate), 'hex'),
    n.name_value,
    x509_commonName(m.certificate),
    x509_notBefore(m.certificate)::text,
    x509_notAfter(m.certificate)::text,
    x509_keyAlgorithm(m.certificate),
    x509_keySize(m.certificate),
    x509_signatureKeyAlgorithm(m.certificate),
    x509_signatureHashAlgorithm(m.certificate),
    ca.name
FROM matching m
LEFT JOIN ca ON ca.id = m.issuer_ca_id
CROSS JOIN LATERAL (
    SELECT encode(raw_value, 'escape') AS name_value, 2 AS src
    FROM x509_altNames_raw(m.certificate)
    WHERE type_num = 2
    UNION ALL
    SELECT x509_commonName(m.certificate), 1
) n
WHERE lower(n.name_value) = lower('{domain}')
   OR lower(n.name_value) LIKE '%.{domain}'";

/// The snapshot query for one domain. The domain is interpolated into SQL
/// (certwatch's API is SimpleQuery — no parameters), so the input is
/// validated to a bare hostname first.
pub fn ct_sql(domain: &str) -> Result<String, String> {
    let domain = domain.to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return Err(format!("invalid domain: {domain}"));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("invalid characters in domain: {domain}"));
    }
    Ok(CT_SQL_TEMPLATE.replace("{domain}", &domain))
}

/// A reused certwatch DB connection for a whole CT fetch (snapshot query,
/// then pq-map's chain query over the same connection).
pub struct Session {
    conninfo: String,
    client: Option<Client>,
    drive: Option<tokio::task::JoinHandle<()>>,
}

impl Session {
    pub fn new(cfg: &CertwatchConfig) -> Self {
        Self {
            conninfo: format!(
                "host={} port={} user={} dbname={}",
                cfg.host, cfg.port, cfg.user, cfg.dbname
            ),
            client: None,
            drive: None,
        }
    }

    /// The snapshot query for one domain, with retries and backoff.
    pub async fn fetch_rows(
        &mut self,
        domain: &str,
        cfg: &CertwatchConfig,
    ) -> Result<Vec<DbRow>, String> {
        let sql = ct_sql(domain)?;
        let messages = self.query_with_retries(&sql, cfg, "certwatch DB").await?;
        parse_db_rows(&messages)
    }

    /// One SimpleQuery round-trip with the timeout and the poison-handling
    /// (hang up the connection on error or timeout). Shared by the
    /// snapshot query and pq-map's chain query.
    pub async fn simple_query_checked(
        &mut self,
        sql: &str,
        cfg: &CertwatchConfig,
    ) -> Result<Vec<SimpleQueryMessage>, String> {
        let client = self.ensure_connected(cfg).await?;
        let result = {
            let query = client.simple_query(sql);
            tokio::time::timeout(cfg.query_timeout, query).await
        };
        match result {
            Ok(Ok(messages)) => Ok(messages),
            Ok(Err(e)) => {
                self.hang_up();
                Err(db_err(e))
            }
            Err(_) => {
                self.hang_up();
                Err("query timeout (no response)".to_string())
            }
        }
    }

    /// Run `sql` with retry/backoff; `what` labels the eprintln trail.
    pub async fn query_with_retries(
        &mut self,
        sql: &str,
        cfg: &CertwatchConfig,
        what: &str,
    ) -> Result<Vec<SimpleQueryMessage>, String> {
        let mut last_error = String::from("not attempted");
        for attempt in 1..=cfg.retries {
            eprintln!(
                "CT: querying {what} at {}:{} (attempt {attempt}/{})",
                cfg.host, cfg.port, cfg.retries
            );
            match self.simple_query_checked(sql, cfg).await {
                Ok(messages) => return Ok(messages),
                Err(e) => {
                    last_error = e;
                    if attempt < cfg.retries {
                        let delay = db_backoff_secs(attempt, cfg.retry_delay);
                        eprintln!(
                            "CT: {last_error}; re-running this query in {delay}s \
                             (attempt {attempt}/{} failed)",
                            cfg.retries
                        );
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                }
            }
        }
        eprintln!("CT: {what} unreachable after {} attempts", cfg.retries);
        Err(last_error)
    }

    async fn ensure_connected(&mut self, cfg: &CertwatchConfig) -> Result<&Client, String> {
        if self.client.is_none() {
            eprintln!(
                "CT: connecting to certwatch DB at {}:{}",
                cfg.host, cfg.port
            );
            let connect = tokio_postgres::connect(&self.conninfo, NoTls);
            let (client, connection) = tokio::time::timeout(cfg.connect_timeout, connect)
                .await
                .map_err(|_| "connect timeout".to_string())?
                .map_err(db_err)?;
            self.drive = Some(tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("CT: db connection dropped: {}", db_err(e));
                }
            }));
            self.client = Some(client);
        }
        Ok(self.client.as_ref().unwrap())
    }

    pub fn close(&mut self) {
        self.hang_up();
    }

    fn hang_up(&mut self) {
        if let Some(drive) = self.drive.take() {
            drive.abort();
        }
        self.client = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.hang_up();
    }
}

pub fn db_backoff_secs(attempt: u32, retry_delay: u64) -> u64 {
    retry_delay
        .saturating_mul(1u64 << (attempt + 1).min(6))
        .min(60)
}

fn parse_db_rows(messages: &[SimpleQueryMessage]) -> Result<Vec<DbRow>, String> {
    messages
        .iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(r) => Some(r),
            _ => None,
        })
        .map(|r| {
            Ok(DbRow {
                cert_id: r
                    .get(0)
                    .ok_or("missing cert id")?
                    .parse()
                    .map_err(|_| "bad cert id")?,
                serial: r.get(1).ok_or("missing serial")?.to_string(),
                dns_name: r.get(2).map(str::to_string),
                common_name: r.get(3).map(str::to_string),
                not_before: r.get(4).map(str::to_string),
                not_after: r.get(5).map(str::to_string),
                key_algorithm: r.get(6).map(str::to_string),
                key_size: r.get(7).and_then(|v| v.parse().ok()),
                sig_key_algorithm: r.get(8).map(str::to_string),
                sig_hash_algorithm: r.get(9).map(str::to_string),
                issuer_ca_name: r.get(10).map(str::to_string),
            })
        })
        .collect()
}

fn db_err(e: tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        let mut s = format!("db error {:?}: {}", db.code(), db.message());
        if let Some(detail) = db.detail() {
            s.push_str(&format!(" ({detail})"));
        }
        return s;
    }
    format!("db error: {e}")
}

/// A certwatch (Postgres) CT lookup for one domain, as its own collection
/// kind — the same domain via the crt.sh HTTP API is a *different*
/// collection (`ct`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtdbRequest {
    pub domain: String,
}

impl CtdbRequest {
    pub fn new(domain: &str) -> Option<Self> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        (!domain.is_empty()).then_some(Self { domain })
    }
}

impl CollectionRequest for CtdbRequest {
    const KIND: &'static str = "ct-db";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("domain", &self.domain);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "domain": self.domain })
    }
}

/// How to drive the async Postgres session. Two legal shapes only:
///
/// - [`Drive::Handle`] — an ambient multi-thread runtime that IS being
///   driven (pq-map calls its collectors from `spawn_blocking`).
/// - [`Drive::Runtime`] — an owned runtime for plain sync callers (batch
///   CLI passes). `Handle::block_on` from an undriven runtime hangs
///   (timers and the DNS blocking pool are never polled), so a sync
///   caller must own the runtime.
pub enum Drive {
    Handle(tokio::runtime::Handle),
    Runtime(tokio::runtime::Runtime),
}

impl Drive {
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        match self {
            Drive::Handle(h) => h.block_on(fut),
            Drive::Runtime(r) => r.block_on(fut),
        }
    }
}

/// Live certwatch read, recorded as a collection. Runs the Postgres query
/// through the configured driver (see [`Drive`]).
pub struct CtdbCollector {
    pub cfg: CertwatchConfig,
    pub drive: std::sync::Arc<Drive>,
}

impl Collector for CtdbCollector {
    type Request = CtdbRequest;
    type Output = Vec<DbRow>;

    fn collect(
        &self,
        _scan: &Scan,
        req: &Self::Request,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let rows = self
            .drive
            .block_on(async {
                let mut session = Session::new(&self.cfg);
                session.fetch_rows(&req.domain, &self.cfg).await
            })
            .map_err(|e| CollectionError::Error {
                native: None,
                message: format!("certwatch: {e}"),
            })?;
        if rows.is_empty() {
            return Err(CollectionError::NotFound {
                native: Some("certwatch: no rows".into()),
            });
        }
        let bytes = serde_json::to_vec(&rows).map_err(|e| CollectionError::Error {
            native: None,
            message: format!("serialize rows: {e}"),
        })?;
        let mut observation = RawObservation::success(serde_json::json!({
            "source": "db",
            "row_count": rows.len(),
        }));
        observation.artifacts.push(RawArtifact {
            role: "ct_rows".into(),
            bytes,
            content_type: "application/json; role=certwatch-rows".into(),
        });
        Ok(observation)
    }

    fn decode(
        &self,
        store: &Store,
        obs: &StoredObservation,
    ) -> crate::evidence::error::Result<Self::Output> {
        let artifact = obs.artifact_by_role("ct_rows").ok_or_else(|| {
            crate::evidence::error::Error::Misuse(format!(
                "CT observation {} has no ct_rows artifact",
                obs.id
            ))
        })?;
        let rows: Vec<DbRow> = serde_json::from_slice(&store.read_artifact(artifact)?)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_backoff_starts_at_cubed_and_caps() {
        assert_eq!(db_backoff_secs(1, 2), 8);
        assert_eq!(db_backoff_secs(2, 2), 16);
        assert_eq!(db_backoff_secs(3, 2), 32);
        assert_eq!(db_backoff_secs(4, 2), 60, "capped at 60s");
        assert_eq!(db_backoff_secs(5, 2), 60);
        assert_eq!(db_backoff_secs(1, 120), 60);
    }

    #[test]
    fn ct_sql_accepts_hostnames_and_rejects_injection() {
        assert!(ct_sql("gov.pl").unwrap().contains("gov.pl"));
        assert!(ct_sql("GOV.PL").unwrap().contains("gov.pl"), "lowercased");
        assert!(ct_sql("").is_err());
        assert!(ct_sql("a'.--").is_err(), "no quotes/semicolons in the SQL");
        assert!(ct_sql("under_score.example").is_err());
    }
}
