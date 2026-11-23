//! Scans and the collection driver.
//!
//! Every tool invocation opens a scan ([`Store::begin_scan`]). The scan
//! records exactly which observations it consumed, each labeled with a usage
//! class (collected / cached / refreshed / historical), so any past run can
//! be reconstructed and its network cost audited.

use crate::evidence::collector::Collector;
use crate::evidence::error::{Error, Result};
use crate::evidence::freshness::{DataStatus, FreshnessRequirement, evaluate};
use crate::evidence::key::{CollectionKey, CollectionRequest};
use crate::evidence::observation::{
    ArtifactLink, ObservationStatus, RawArtifact, RawObservation, StoredObservation,
};
use crate::evidence::store::{Store, Usage, now_secs};
use std::collections::HashSet;

/// Handle for one tool run. All collection goes through a scan so that
/// consumption is recorded. Cloning the store is cheap; a scan owns its
/// store handle so it can move across threads.
#[derive(Clone)]
pub struct Scan {
    store: Store,
    id: i64,
}

impl Scan {
    pub(crate) fn new(store: &Store, id: i64) -> Self {
        Self {
            store: store.clone(),
            id,
        }
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Mark the run finished. A scan that is never finished (crash) shows
    /// `finished_at = NULL` — truthful.
    pub fn finish(self) -> Result<()> {
        self.store.finish_scan(self.id)
    }

    /// Record an observation for a collection whose result was obtained
    /// out-of-band (e.g. a TLS handshake performed on an existing socket, or
    /// a Postgres read path living outside pq-core). The raw observation is
    /// persisted under the request's canonical identity with the same
    /// freshness math as a driven collection; usage is recorded as
    /// `collected`.
    pub fn record<R: CollectionRequest>(
        &self,
        req: &R,
        raw: RawObservation,
    ) -> Result<StoredObservation> {
        let key = req.key();
        let policy_name = raw
            .policy_name
            .clone()
            .unwrap_or(std::borrow::Cow::Borrowed("default"));
        let policy = self.store.policy(R::KIND, &policy_name)?;
        let observed_at = now_secs();
        let fresh_until = policy.fresh_until(observed_at, raw.fresh_hint);
        let stored = self.store.ingest(
            self.id,
            &key,
            R::KIND,
            &req.stored_params(),
            &raw,
            fresh_until,
            Some(&policy),
        )?;
        self.store
            .record_usage(self.id, stored.id, Usage::Collected)?;
        Ok(stored)
    }

    /// The collection path: evaluate freshness, serve from the store when the
    /// requirement and policy permit, otherwise collect — blocking, on-read —
    /// through the in-process single-flight so concurrent identical requests
    /// share one collection.
    pub fn collect<C: Collector>(
        &self,
        collector: &C,
        req: C::Request,
        freshness: FreshnessRequirement,
    ) -> Result<Collected<C::Output>> {
        let key = CollectionKey::compute(C::Request::KIND, &req);
        if let FreshnessRequirement::Historical { at } = freshness {
            return self.historical(collector, &req, &key, at.timestamp());
        }

        // Store-only read: whatever we have, honestly labeled, no network.
        if let FreshnessRequirement::Cached = freshness {
            return match self.store.latest_usable_observation(&key)? {
                Some(obs) => {
                    let policy_name = collector.policy_name(&req, Some(obs.status)).into_owned();
                    let policy = self.store.policy(C::Request::KIND, &policy_name)?;
                    let data_status = evaluate(now_secs(), Some(&obs), &policy);
                    self.store.record_usage(self.id, obs.id, Usage::Cached)?;
                    let data = collector.decode(&self.store, &obs)?;
                    Ok(Collected {
                        usage: Usage::Cached,
                        data_status,
                        observation: Some(obs),
                        data: Some(data),
                        failure: None,
                    })
                }
                None => Ok(Collected {
                    usage: Usage::Cached,
                    data_status: DataStatus::Unavailable,
                    observation: None,
                    data: None,
                    failure: None,
                }),
            };
        }

        let now = now_secs();
        let latest = self.store.latest_usable_observation(&key)?;
        let policy_name = collector
            .policy_name(&req, latest.as_ref().map(|o| o.status))
            .into_owned();
        let policy = self.store.policy(C::Request::KIND, &policy_name)?;
        let status = evaluate(now, latest.as_ref(), &policy);

        let satisfied = match (&freshness, status) {
            (_, DataStatus::Unavailable) | (_, DataStatus::Expired) => false,
            (FreshnessRequirement::Refresh, _) => false,
            (FreshnessRequirement::MaxAge(max), DataStatus::Fresh | DataStatus::Stale) => {
                let latest = latest
                    .as_ref()
                    .expect("status Fresh/Stale implies an observation");
                now - latest.observed_at <= max.as_secs() as i64
            }
            (FreshnessRequirement::Cached | FreshnessRequirement::Historical { .. }, _) => {
                return Err(Error::Misuse(
                    "cached/historical requirements handled above".into(),
                ));
            }
        };

        if satisfied {
            let obs = latest.expect("satisfied requirement implies an observation");
            self.store.record_usage(self.id, obs.id, Usage::Cached)?;
            let data = collector.decode(&self.store, &obs)?;
            return Ok(Collected {
                usage: Usage::Cached,
                data_status: status,
                observation: Some(obs),
                data: Some(data),
                failure: None,
            });
        }

        // Blocking revalidation (or first collection), single-flighted.
        let guard = self.store.inner.flights.enter(*key.as_bytes());
        if guard.leader {
            let prior = self.store.latest_usable(&key)?;
            let prior_existed = prior.is_some();
            match collector.collect(self, &req, prior.as_ref()) {
                Ok(raw) => {
                    let mut raw = raw;
                    if let Some(prior_id) = raw.confirms {
                        self.carry_forward_confirmed_roles(prior_id, &mut raw)?;
                    }
                    let ingest_name = raw.policy_name.clone().unwrap_or_else(|| {
                        collector
                            .policy_name(&req, Some(raw.status))
                            .into_owned()
                            .into()
                    });
                    let ingest_policy = self.store.policy(C::Request::KIND, &ingest_name)?;
                    let observed_at = now_secs();
                    let fresh_until = ingest_policy.fresh_until(observed_at, raw.fresh_hint);
                    let stored = self.store.ingest(
                        self.id,
                        &key,
                        C::Request::KIND,
                        &req.stored_params(),
                        &raw,
                        fresh_until,
                        Some(&ingest_policy),
                    )?;
                    guard.complete(stored.id);
                    let usage = if prior_existed {
                        Usage::Refreshed
                    } else {
                        Usage::Collected
                    };
                    self.store.record_usage(self.id, stored.id, usage)?;
                    let data = collector.decode(&self.store, &stored)?;
                    Ok(Collected {
                        usage,
                        data_status: DataStatus::Fresh,
                        observation: Some(stored),
                        data: Some(data),
                        failure: None,
                    })
                }
                Err(failure) => {
                    let raw = failure.to_raw();
                    // Failure observations carry no freshness claim.
                    let stored = self.store.ingest(
                        self.id,
                        &key,
                        C::Request::KIND,
                        &req.stored_params(),
                        &raw,
                        None,
                        Some(&policy),
                    )?;
                    guard.complete(stored.id);
                    self.resolve_failure(collector, &req, &key, &stored)
                }
            }
        } else {
            let obs_id = guard.wait()?;
            let produced = self.store.observation_by_id(obs_id)?.ok_or_else(|| {
                Error::Misuse(format!(
                    "single-flight produced missing observation {obs_id}"
                ))
            })?;
            if produced.status.is_usable() {
                self.store
                    .record_usage(self.id, produced.id, Usage::Cached)?;
                let data = collector.decode(&self.store, &produced)?;
                Ok(Collected {
                    usage: Usage::Cached,
                    data_status: DataStatus::Fresh,
                    observation: Some(produced),
                    data: Some(data),
                    failure: None,
                })
            } else {
                self.resolve_failure(collector, &req, &key, &produced)
            }
        }
    }

    /// A failed collection: record it, keep the last successful result as the
    /// fallback (labeled honestly by its age), and surface the failure.
    fn resolve_failure<C: Collector>(
        &self,
        collector: &C,
        req: &C::Request,
        key: &CollectionKey,
        failed: &StoredObservation,
    ) -> Result<Collected<C::Output>> {
        let failure = RecordedFailure {
            status: failed.status,
            native_status: failed.native_status.clone(),
            observed_at: failed.observed_at,
            message: failed
                .metadata
                .get("error")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        };
        let fallback = self.store.latest_usable(key)?;
        let fallback = match fallback {
            // latest_usable never returns the failed observation (status
            // filter); any hit predates the failure.
            Some(o) => o,
            None => {
                return Ok(Collected {
                    usage: Usage::Cached,
                    data_status: DataStatus::Unavailable,
                    observation: None,
                    data: None,
                    failure: Some(failure),
                });
            }
        };
        let policy_name = collector
            .policy_name(req, Some(fallback.status))
            .into_owned();
        let policy = self.store.policy(C::Request::KIND, &policy_name)?;
        let status = evaluate(now_secs(), Some(&fallback), &policy);
        self.store
            .record_usage(self.id, fallback.id, Usage::Cached)?;
        let data = collector.decode(&self.store, &fallback)?;
        Ok(Collected {
            usage: Usage::Cached,
            data_status: status,
            observation: Some(fallback),
            data: Some(data),
            failure: Some(failure),
        })
    }

    /// HTTP 304: the fresh observation confirms the cached representation.
    /// Carry the prior observation's artifact roles forward (the dedup store
    /// re-links them to the same content hash — no duplicate body artifact),
    /// except roles the new outcome itself provides (fresh response headers).
    fn carry_forward_confirmed_roles(&self, prior_id: i64, raw: &mut RawObservation) -> Result<()> {
        let Some(prior) = self.store.observation_by_id(prior_id)? else {
            return Ok(());
        };
        let provided: HashSet<String> = raw.artifacts.iter().map(|a| a.role.to_string()).collect();
        let to_carry: Vec<ArtifactLink> = prior
            .artifacts
            .iter()
            .filter(|link| !provided.contains(&link.role))
            .cloned()
            .collect();
        for link in to_carry {
            let bytes = self.store.read_artifact(&link.artifact)?;
            raw.artifacts.push(RawArtifact {
                role: link.role.into(),
                bytes,
                content_type: link.artifact.content_type.into(),
            });
        }
        Ok(())
    }

    fn historical<C: Collector>(
        &self,
        collector: &C,
        req: &C::Request,
        key: &CollectionKey,
        at: i64,
    ) -> Result<Collected<C::Output>> {
        let obs = self.store.latest_usable_before(key, Some(at))?;
        let Some(obs) = obs else {
            return Ok(Collected {
                usage: Usage::Historical,
                data_status: DataStatus::Unavailable,
                observation: None,
                data: None,
                failure: None,
            });
        };
        let policy_name = collector.policy_name(req, Some(obs.status)).into_owned();
        let policy = self.store.policy(C::Request::KIND, &policy_name)?;
        let status = evaluate(at, Some(&obs), &policy);
        self.store
            .record_usage(self.id, obs.id, Usage::Historical)?;
        let data = collector.decode(&self.store, &obs)?;
        Ok(Collected {
            usage: Usage::Historical,
            data_status: status,
            observation: Some(obs),
            data: Some(data),
            failure: None,
        })
    }
}

/// The outcome of one collection request against the store.
pub struct Collected<O> {
    /// What this run did: collected / cached / refreshed / historical.
    pub usage: Usage,
    /// Honest label of the returned data's state.
    pub data_status: DataStatus,
    /// The observation consumed, when one exists.
    pub observation: Option<StoredObservation>,
    /// Typed data decoded from the observation, when one exists.
    pub data: Option<O>,
    /// The failure recorded when an attempted collection failed (the store
    /// kept the last successful result).
    pub failure: Option<RecordedFailure>,
}

/// A recorded failed attempt, preserved without erasing the last success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedFailure {
    pub status: ObservationStatus,
    pub native_status: Option<String>,
    pub observed_at: i64,
    pub message: Option<String>,
}
