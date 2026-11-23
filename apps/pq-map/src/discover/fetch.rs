use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;

use pq_core::evidence::FreshnessRequirement;
use pq_core::evidence::collector::CollectionError;
use pq_core::evidence::collector::Collector;
use pq_core::evidence::collectors::ct::{CtCollector, CtRequest, CtShRow};
use pq_core::evidence::collectors::ctdb::{
    CertwatchConfig, CtdbCollector, CtdbRequest, DbRow, Session,
};
use pq_core::evidence::key::CollectionRequest;
use pq_core::evidence::observation::StoredObservation;
use pq_core::evidence::observation::{RawArtifact, RawObservation};
use pq_core::evidence::scan::Scan;

use crate::config::Config;
use crate::model::{Certificate, Provenance};

use super::ct;
use super::ctdb;

/// Map's env-parsed CT knobs, as the core certwatch config.
fn certwatch_cfg(cfg: &Config) -> CertwatchConfig {
    CertwatchConfig {
        host: cfg.db_host.clone(),
        port: cfg.db_port,
        user: cfg.db_user.clone(),
        dbname: cfg.db_name.clone(),
        connect_timeout: std::time::Duration::from_secs(cfg.db_connect_timeout),
        query_timeout: std::time::Duration::from_secs(cfg.db_query_timeout),
        retries: cfg.retries,
        retry_delay: cfg.retry_delay,
    }
}

pub struct FetchOutcome {
    pub certs: BTreeMap<String, Certificate>,
    pub provenance: Provenance,
    /// "db" or "http" for a fresh snapshot; None when served from the store.
    pub source: Option<&'static str>,
}

/// CT snapshot via the store: certwatch DB first, crt.sh HTTP fallback,
/// the store's last success as the stale fallback. The file caches are
/// gone; freshness is the store's job (`--refresh` → `Refresh`, else the
/// 30-day policy).
pub async fn obtain(
    domain: &str,
    cfg: &Config,
    refresh: bool,
    ev: &crate::store::MapEvidence,
) -> Result<FetchOutcome, Error> {
    let owned = domain.to_string();
    let cfg = cfg.clone();
    let rt = tokio::runtime::Handle::current();
    let ev = ev.clone();
    tokio::task::spawn_blocking(move || obtain_blocking(&owned, &cfg, refresh, &ev, &rt))
        .await
        .map_err(|_| Error::Join)?
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("task join failed")]
    Join,
    #[error("no CT data available")]
    NoCtData,
}

fn obtain_blocking(
    domain: &str,
    cfg: &Config,
    refresh: bool,
    ev: &crate::store::MapEvidence,
    rt: &tokio::runtime::Handle,
) -> Result<FetchOutcome, Error> {
    let requirement = if refresh {
        FreshnessRequirement::Refresh
    } else {
        FreshnessRequirement::MaxAge(std::time::Duration::from_secs(cfg.cache_ttl))
    };

    // 1. Certwatch DB path (its own collection; retry/backoff live in ctdb).
    let Some(db_req) = CtdbRequest::new(domain) else {
        return Err(Error::NoCtData);
    };
    let db_collector = CtdbCollector {
        cfg: certwatch_cfg(cfg),
        drive: Arc::new(pq_core::evidence::collectors::ctdb::Drive::Handle(
            rt.clone(),
        )),
    };
    match ev
        .scan
        .collect(&db_collector, db_req.clone(), requirement.clone())
    {
        Ok(outcome) => {
            let Some(rows) = outcome.data else {
                eprintln!("CT: certwatch DB returned no usable certificates");
                return http_fallback(domain, cfg, ev, requirement, rt);
            };
            let certs = ct::certificates_from_db(&rows, Utc::now());
            if certs.is_empty() {
                eprintln!("CT: certwatch DB returned no usable certificates");
                return http_fallback(domain, cfg, ev, requirement, rt);
            }
            let certs = attach_chains(domain, refresh, certs, cfg, ev, rt);
            return Ok(FetchOutcome {
                certs,
                provenance: Provenance::Fresh,
                source: Some("db"),
            });
        }
        Err(e) => eprintln!("CT: falling back to crt.sh HTTP: {e}"),
    }
    http_fallback(domain, cfg, ev, requirement, rt)
}

/// crt.sh HTTP via the shared CT collector, then the store's last success
/// as the stale fallback.
fn http_fallback(
    domain: &str,
    cfg: &Config,
    ev: &crate::store::MapEvidence,
    requirement: FreshnessRequirement,
    rt: &tokio::runtime::Handle,
) -> Result<FetchOutcome, Error> {
    let req = CtRequest::domain(domain).map_err(|_| Error::NoCtData)?;
    let collector = CtCollector {
        http: ev.http.clone(),
    };
    let outcome = match ev.scan.collect(&collector, req.clone(), requirement) {
        Ok(outcome) if outcome.failure.is_none() => outcome,
        Ok(outcome) => {
            eprintln!(
                "CT: crt.sh HTTP collection failed: {:?}",
                outcome.failure.map(|f| f.status)
            );
            return stale_fallback(domain, ev);
        }
        Err(e) => {
            eprintln!("CT: {e}");
            return stale_fallback(domain, ev);
        }
    };
    {
        let stored = outcome.observation.ok_or(Error::NoCtData)?;
        let artifact = stored
            .artifact_by_role("ct_response")
            .ok_or(Error::NoCtData)?;
        let bytes = ev
            .store
            .read_artifact(artifact)
            .map_err(|_| Error::NoCtData)?;
        let rows: Vec<CtShRow> = serde_json::from_slice(&bytes).map_err(|_| Error::NoCtData)?;
        let certs = ct::certificates(&rows, Utc::now());
        if certs.is_empty() {
            eprintln!("CT: crt.sh returned no certificates for {domain}");
        }
        let certs = attach_chains(domain, true, certs, cfg, ev, rt);
        Ok(FetchOutcome {
            certs,
            provenance: Provenance::Fresh,
            source: Some("http"),
        })
    }
}

/// Both live sources failed: the store keeps the last success, per source.
fn stale_fallback(domain: &str, ev: &crate::store::MapEvidence) -> Result<FetchOutcome, Error> {
    for (kind, req_key) in [
        ("ct-db", CtdbRequest::new(domain).map(|r| r.key())),
        ("ct", CtRequest::domain(domain).ok().map(|r| r.key())),
    ] {
        let Some(key) = req_key else { continue };
        if let Ok(history) = ev.store.observation_history(&key, 1)
            && let Some(obs) = history.first()
            && let Some(certs) = certs_from_stored(ev, kind, obs)
        {
            let age = obs
                .observed_at_time()
                .map(|t| (Utc::now() - t).num_seconds().max(0) as u64);
            eprintln!(
                "WARNING: CT sources unavailable; using stored {kind} snapshot from {}s ago",
                age.unwrap_or(0)
            );
            return Ok(FetchOutcome {
                certs: ct::revive_certs(certs.into_values().collect(), Utc::now()),
                provenance: Provenance::Stale { age_secs: age },
                source: None,
            });
        }
    }
    Err(Error::NoCtData)
}

/// Read a stored CT observation back into certificates, per source kind.
fn certs_from_stored(
    ev: &crate::store::MapEvidence,
    kind: &str,
    obs: &StoredObservation,
) -> Option<BTreeMap<String, Certificate>> {
    let now = Utc::now();
    match kind {
        "ct-db" => {
            let rows: Vec<DbRow> = serde_json::from_slice(
                &ev.store
                    .read_artifact(obs.artifact_by_role("ct_rows")?)
                    .ok()?,
            )
            .ok()?;
            let certs = ct::certificates_from_db(&rows, now);
            (!certs.is_empty()).then_some(certs)
        }
        "ct" => {
            let rows: Vec<CtShRow> = serde_json::from_slice(
                &ev.store
                    .read_artifact(obs.artifact_by_role("ct_response")?)
                    .ok()?,
            )
            .ok()?;
            let certs = ct::certificates(&rows, now);
            (!certs.is_empty()).then_some(certs)
        }
        _ => None,
    }
}

/// CT chain lookups (certwatch DB) for one domain, cached as their own
/// collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRequest {
    pub domain: String,
}

impl ChainRequest {
    pub fn new(domain: &str) -> Option<Self> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        (!domain.is_empty()).then_some(Self { domain })
    }
}

impl CollectionRequest for ChainRequest {
    const KIND: &'static str = "ct-chain";
    fn write_canonical(&self, w: &mut pq_core::evidence::key::CanonicalWriter) {
        w.str_field("domain", &self.domain);
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "domain": self.domain })
    }
}

/// Live certwatch chain read for the current leaf set, recorded as a
/// collection. The cache key is the domain (chain content follows the CT
/// snapshot); the live leaf ids ride on the collector.
pub struct ChainCollector {
    pub cfg: Config,
    pub drive: std::sync::Arc<pq_core::evidence::collectors::ctdb::Drive>,
    /// Current cert leaf ids, queried on a cache miss.
    pub leaf_ids: Vec<u64>,
}

impl Collector for ChainCollector {
    type Request = ChainRequest;
    type Output = BTreeMap<u64, Vec<crate::model::ChainEntry>>;

    fn collect(
        &self,
        _scan: &Scan,
        _req: &Self::Request,
        _prior: Option<&StoredObservation>,
    ) -> Result<RawObservation, CollectionError> {
        let chains = self
            .drive
            .block_on(async {
                let cw = certwatch_cfg(&self.cfg);
                let mut session = Session::new(&cw);
                ctdb::chain_rows(&mut session, &self.leaf_ids, &cw).await
            })
            .map_err(|e| CollectionError::Error {
                native: None,
                message: format!("certwatch chains: {e}"),
            })?;
        if chains.is_empty() {
            return Err(CollectionError::NotFound {
                native: Some("certwatch: no chains".into()),
            });
        }
        let bytes = serde_json::to_vec(&chains).map_err(|e| CollectionError::Error {
            native: None,
            message: format!("serialize chains: {e}"),
        })?;
        let mut observation = RawObservation::success(serde_json::json!({ "source": "db" }));
        observation.artifacts.push(RawArtifact {
            role: "ct_chains".into(),
            bytes,
            content_type: "application/json; role=certwatch-chains".into(),
        });
        Ok(observation)
    }

    fn decode(
        &self,
        store: &pq_core::evidence::Store,
        obs: &StoredObservation,
    ) -> pq_core::evidence::Result<Self::Output> {
        let artifact = obs.artifact_by_role("ct_chains").ok_or_else(|| {
            pq_core::evidence::error::Error::Misuse(format!(
                "chain observation {} has no ct_chains artifact",
                obs.id
            ))
        })?;
        let chains: BTreeMap<u64, Vec<crate::model::ChainEntry>> =
            serde_json::from_slice(&store.read_artifact(artifact)?)?;
        Ok(chains)
    }
}

/// Leaf ids for the chain query ride on the collector (see
/// `ChainCollector`); nothing to precompute here.
fn attach_chains(
    domain: &str,
    refresh: bool,
    mut certs: BTreeMap<String, Certificate>,
    cfg: &Config,
    ev: &crate::store::MapEvidence,
    rt: &tokio::runtime::Handle,
) -> BTreeMap<String, Certificate> {
    let leaf_ids: Vec<u64> = {
        let mut ids: Vec<u64> = certs
            .values()
            .filter_map(|c| c.ct_ids.first().copied())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    if leaf_ids.is_empty() {
        return certs;
    }

    let requirement = if refresh {
        FreshnessRequirement::Refresh
    } else {
        FreshnessRequirement::MaxAge(std::time::Duration::from_secs(cfg.cache_ttl))
    };
    #[derive(Clone)]
    struct _Req;
    let _ = _Req;

    let Some(req) = ChainRequest::new(domain) else {
        return certs;
    };
    let collector = ChainCollector {
        cfg: cfg.clone(),
        drive: Arc::new(pq_core::evidence::collectors::ctdb::Drive::Handle(
            rt.clone(),
        )),
        leaf_ids,
    };
    match ev.scan.collect(&collector, req, requirement) {
        Ok(outcome) => {
            let chains = outcome.data.unwrap_or_default();
            for cert in certs.values_mut() {
                if let Some(id) = cert.ct_ids.first() {
                    cert.chain = chains.get(id).cloned().unwrap_or_default();
                }
            }
        }
        Err(e) => eprintln!("CT: chain query failed, proceeding without stored chains: {e}"),
    }
    certs
}
