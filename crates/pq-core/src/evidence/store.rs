//! The evidence store: opening, policies, observation persistence and reads,
//! scan history. The public surface consumers touch; see [`crate::evidence`]
//! docs for the design.

use crate::evidence::artifact::{ArtifactStore, FsArtifactStore};
use crate::evidence::error::{Error, Result};
use crate::evidence::flight::FlightTable;
use crate::evidence::key::CollectionKey;
use crate::evidence::observation::{
    ArtifactLink, ArtifactMeta, ObservationStatus, RawObservation, StoredObservation,
};
use crate::evidence::policy::Policy;
use crate::evidence::schema;
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) struct Inner {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) artifacts: FsArtifactStore,
    pub(crate) flights: Arc<FlightTable>,
    pub(crate) data_dir: PathBuf,
}

impl Inner {
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.conn.lock().expect("store connection mutex");
        f(&conn)
    }
}

#[derive(Clone, Debug)]
pub struct StoreOptions {
    /// SQLite busy timeout for multi-process CLI access.
    pub busy_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_secs(5),
        }
    }
}

/// The shared evidence and knowledge store.
///
/// Cheap to clone; shares one SQLite connection guarded by a mutex (CLI-scale
/// write volume) plus the filesystem artifact store.
#[derive(Clone)]
pub struct Store {
    pub(crate) inner: Arc<Inner>,
}

impl Store {
    /// Open (creating if needed) the store at `data_dir`: `evidence.db` plus
    /// an `artifacts/` subtree.
    pub fn open(data_dir: &Path) -> Result<Store> {
        Self::open_with(data_dir, StoreOptions::default())
    }

    /// Open with non-default options.
    pub fn open_with(data_dir: &Path, opts: StoreOptions) -> Result<Store> {
        std::fs::create_dir_all(data_dir)?;
        let conn = Connection::open(data_dir.join("evidence.db"))?;
        // PRAGMAs per spec: foreign keys, WAL, busy timeout for multi-process
        // CLI access. All timestamps are UTC Unix seconds.
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(opts.busy_timeout)?;
        schema::migrate(&conn)?;
        let conn = Mutex::new(conn);
        let artifacts = FsArtifactStore::new(
            data_dir.join("artifacts"),
            Arc::new(Mutex::new(
                // The artifact catalog shares the same SQLite file; a dedicated
                // connection keeps file I/O (which must not hold the main lock)
                // separate from other queries.
                {
                    let c = Connection::open(data_dir.join("evidence.db"))?;
                    c.pragma_update(None, "foreign_keys", "ON")?;
                    c.pragma_update(None, "journal_mode", "WAL")?;
                    c.busy_timeout(opts.busy_timeout)?;
                    c
                },
            )),
        );
        Ok(Store {
            inner: Arc::new(Inner {
                conn,
                artifacts,
                flights: Arc::new(FlightTable::new()),
                data_dir: data_dir.to_path_buf(),
            }),
        })
    }

    /// Open the store at the platform default location:
    /// `$XDG_DATA_HOME/pq-intel` or `~/.local/share/pq-intel`, containing
    /// `evidence.db`.
    pub fn open_default() -> Result<Store> {
        Self::open(&super::default_dir()?)
    }

    /// **Low-level seam.** Run one closure with the store's SQLite
    /// connection, under the store's lock.
    ///
    /// This exists for the tasking plane (the `pq-tasks` crate), whose
    /// rows live in the same SQLite file as the evidence but whose access
    /// does not go through the store's observation/freshness machinery.
    /// Everything else should use the public API: direct connection access
    /// bypasses every store invariant (append-only, freshness math,
    /// single-flight, usage recording). Callers must not hold the
    /// connection across `await` points or spawn store calls from inside
    /// the closure (the mutex is not reentrant).
    pub fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.inner.with_conn(f)
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    /// Introspection (used by tests and operational checks): how many
    /// participants are joined to the in-flight collection for `key`.
    #[doc(hidden)]
    pub fn in_flight_participants(&self, key: &CollectionKey) -> usize {
        self.inner.flights.participants(*key.as_bytes())
    }

    // ---- policies ----

    /// Effective policy for `(kind, name)`, falling back to `(kind, default)`
    /// when the specific name has no row.
    pub fn policy(&self, kind: &str, name: &str) -> Result<Policy> {
        let row = |conn: &Connection, name: &str| -> Result<Option<Policy>> {
            Ok(conn
                .query_row(
                    "SELECT kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs
                     FROM refresh_policies WHERE kind = ?1 AND name = ?2",
                    rusqlite::params![kind, name],
                    policy_from_row,
                )
                .optional()?)
        };
        self.inner
            .with_conn(|conn| row(conn, name))?
            .or_else(|| {
                self.inner
                    .with_conn(|conn| row(conn, "default"))
                    .expect("default policy fallback")
            })
            .ok_or_else(|| {
                Error::Misuse(format!(
                    "no refresh policy for kind `{kind}` (neither `{name}` nor `default`)"
                ))
            })
    }

    /// Insert or update a policy (policies are data, not code).
    pub fn set_policy(&self, policy: &Policy) -> Result<()> {
        self.inner.with_conn(|conn| {
            conn.execute(
                "INSERT INTO refresh_policies (kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(kind, name) DO UPDATE SET
                     fresh_for_secs = excluded.fresh_for_secs,
                     allow_stale = excluded.allow_stale,
                     stale_for_secs = excluded.stale_for_secs,
                     ttl_min_secs = excluded.ttl_min_secs,
                     ttl_max_secs = excluded.ttl_max_secs",
                rusqlite::params![
                    policy.kind,
                    policy.name,
                    policy.fresh_for.map(|d| d.as_secs() as i64),
                    i64::from(policy.allow_stale),
                    policy.stale_for.map(|d| d.as_secs() as i64),
                    policy.ttl_min.map(|d| d.as_secs() as i64),
                    policy.ttl_max.map(|d| d.as_secs() as i64),
                ],
            )?;
            Ok(())
})
    }

    pub fn policies(&self) -> Result<Vec<Policy>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs
                 FROM refresh_policies ORDER BY kind, name",
            )?;
            let rows = stmt
                .query_map([], policy_from_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
})
    }

    // ---- artifacts ----

    /// Read artifact content back (decompressed).
    pub fn read_artifact(&self, meta: &ArtifactMeta) -> Result<Vec<u8>> {
        self.inner
            .artifacts
            .get(&meta.hash)?
            .ok_or_else(|| Error::ArtifactFileMissing(meta.hex()))
    }

    pub fn artifact_store(&self) -> &FsArtifactStore {
        &self.inner.artifacts
    }

    // ---- history / reconstruction ----

    /// The most recent `limit` observations for a collection identity,
    /// newest first. Failed observations are preserved alongside successful
    /// ones.
    pub fn observation_history(
        &self,
        key: &CollectionKey,
        limit: usize,
    ) -> Result<Vec<StoredObservation>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT o.id, o.status, o.native_status, o.observed_at, o.source_time, o.fresh_until, o.metadata, o.scan_id, c.kind, c.collection_key
                 FROM observations o JOIN collections c ON c.id = o.collection_id
                 WHERE c.collection_key = ?1
                 ORDER BY o.observed_at DESC, o.id DESC LIMIT ?2",
            )?;
            let mut rows = stmt
                .query_map(rusqlite::params![key.as_bytes().as_slice(), limit as i64], obs_row_mapper())?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for o in &mut rows {
                fill_links(conn, o)?;
            }
            Ok(rows)
})
    }

    /// Recorded scans, newest first.
    pub fn scans(&self, limit: usize) -> Result<Vec<ScanSummary>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, tool, invocation, started_at, finished_at FROM scans ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![limit as i64], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let summaries = rows
                .into_iter()
                .map(|(id, tool, invocation, started_at, finished_at)| {
                    Ok(ScanSummary {
                        id,
                        tool,
                        invocation: serde_json::from_str(&invocation)?,
                        started_at,
                        finished_at,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(summaries)
        })
    }

    /// Which observations a scan consumed, with usage labels.
    pub fn scan_observations(&self, scan_id: i64) -> Result<Vec<(i64, Usage)>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT observation_id, usage FROM scan_observations WHERE scan_id = ?1 ORDER BY observation_id",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![scan_id], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(id, usage)| {
                    Ok((
                        id,
                        Usage::from_str(&usage)
                            .ok_or_else(|| Error::Misuse(format!("bad usage `{usage}`")))?,
                    ))
                })
                .collect()
        })
    }

    /// Begin a scan: every tool invocation creates a scan row recording the
    /// tool, its invocation, and (via [`Scan`]) exactly which observations it
    /// consumed.
    pub fn begin_scan(
        &self,
        tool: &str,
        invocation: serde_json::Value,
    ) -> Result<crate::evidence::scan::Scan> {
        let now = now_secs();
        let id = self.inner.with_conn(|conn| {
            conn.execute(
                "INSERT INTO scans (tool, invocation, started_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![tool, invocation.to_string(), now],
            )?;
            Ok(conn.last_insert_rowid())
        })?;
        Ok(crate::evidence::scan::Scan::new(self, id))
    }

    // ---- observation persistence (driver-facing) ----

    /// Persist an observation with its artifacts (files first, then catalog
    /// and links inside one transaction) and maintain `collection_state`.
    /// Append-only: nothing here ever deletes or overwrites an existing row.
    #[allow(clippy::too_many_arguments)] // the row shape, one argument per column
    pub(crate) fn ingest(
        &self,
        scan_id: i64,
        key: &CollectionKey,
        kind: &str,
        params: &serde_json::Value,
        raw: &RawObservation,
        fresh_until: Option<i64>,
        policy: Option<&Policy>,
    ) -> Result<StoredObservation> {
        // Artifacts first: files must be durable before any DB reference
        // exists (crash-safe ordering).
        let mut metas = Vec::with_capacity(raw.artifacts.len());
        for a in &raw.artifacts {
            metas.push(self.inner.artifacts.put(&a.bytes, &a.content_type)?);
        }

        self.inner.with_conn(|conn| {
            let policy_id = match policy {
                Some(p) => conn
                    .query_row(
                        "SELECT id FROM refresh_policies WHERE kind = ?1 AND name = ?2",
                        rusqlite::params![p.kind, p.name],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?,
                None => None,
            };
            let collection_id = {
                conn.execute(
                    "INSERT INTO collections (collection_key, kind, params, policy_id) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(collection_key) DO NOTHING",
                    rusqlite::params![key.as_bytes().as_slice(), kind, params.to_string(), policy_id],
                )?;
                let id: i64 = conn.query_row(
                    "SELECT id FROM collections WHERE collection_key = ?1",
                    rusqlite::params![key.as_bytes().as_slice()],
                    |r| r.get(0),
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO collection_state (collection_id) VALUES (?1)",
                    rusqlite::params![id],
                )?;
                id
            };
            let now = now_secs();
            conn.execute(
                "INSERT INTO observations (collection_id, scan_id, status, native_status, observed_at, source_time, fresh_until, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    collection_id,
                    scan_id,
                    raw.status.as_str(),
                    raw.native_status,
                    now,
                    raw.source_time.map(|t| t.timestamp()),
                    fresh_until,
                    raw.metadata.to_string(),
                ],
            )?;
            let obs_id = conn.last_insert_rowid();
            for (a, meta) in raw.artifacts.iter().zip(&metas) {
                conn.execute(
                    "INSERT OR IGNORE INTO observation_artifacts (observation_id, artifact_id, role) VALUES (?1, ?2, ?3)",
                    rusqlite::params![obs_id, meta_id(conn, &meta.hash)?, a.role],
                )?;
            }
            // Maintain collection_state: freshness pointer for the (future)
            // runner, plus the last-attempt pointer so consumers never need
            // to search for the newest observation.
            conn.execute(
                "UPDATE collection_state
                 SET next_refresh_at = ?1,
                     latest_observation_id = ?2
                 WHERE collection_id = ?3",
                rusqlite::params![fresh_until, obs_id, collection_id],
            )?;

            let mut stored = StoredObservation {
                id: obs_id,
                key: *key,
                kind: kind.to_string(),
                status: raw.status,
                native_status: raw.native_status.clone(),
                observed_at: now,
                source_time: raw.source_time.map(|t| t.timestamp()),
                fresh_until,
                metadata: raw.metadata.clone(),
                artifacts: Vec::new(),
                scan_id,
            };
            fill_links(conn, &mut stored)?;
            Ok(stored)
})
    }

    pub(crate) fn observation_by_id(&self, id: i64) -> Result<Option<StoredObservation>> {
        self.inner.with_conn(|conn| {
            let obs = conn
                .query_row(
                    "SELECT o.id, o.status, o.native_status, o.observed_at, o.source_time, o.fresh_until, o.metadata, o.scan_id, c.kind, c.collection_key
                     FROM observations o JOIN collections c ON c.id = o.collection_id
                     WHERE o.id = ?1",
                    rusqlite::params![id],
                    obs_row_mapper(),
                )
                .optional()?;
            let mut obs = match obs {
                Some(o) => o,
                None => return Ok(None),
            };
            fill_links(conn, &mut obs)?;
            Ok(Some(obs))
})
    }

    /// Latest observation for a collection identity — the last collection
    /// attempt regardless of outcome (success, not_found, timeout,
    /// rate_limited, error).
    pub fn latest_observation(&self, key: &CollectionKey) -> Result<Option<StoredObservation>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT o.id, o.status, o.native_status, o.observed_at, o.source_time, o.fresh_until, o.metadata, o.scan_id, c.kind, c.collection_key
                 FROM observations o JOIN collections c ON c.id = o.collection_id
                 WHERE c.collection_key = ?1
                 ORDER BY o.observed_at DESC, o.id DESC LIMIT 1",
            )?;
            let mut obs = stmt.query_row(rusqlite::params![key.as_bytes().as_slice()], obs_row_mapper()).optional()?;
            if let Some(o) = &mut obs {
                fill_links(conn, o)?;
            }
            Ok(obs)
        })
    }

    /// Latest usable observation (a success or a valid negative answer) for a
    /// collection identity. A failed collection never overwrites this —
    /// consumers get the last good result plus, via
    /// [`Collected::failure`](crate::evidence::Collected::failure), the
    /// reason the newest attempt failed.
    pub fn latest_usable_observation(
        &self,
        key: &CollectionKey,
    ) -> Result<Option<StoredObservation>> {
        self.latest_usable(key)
    }

    /// Latest usable observation observed at or before `before` (UTC secs).
    pub(crate) fn latest_usable(&self, key: &CollectionKey) -> Result<Option<StoredObservation>> {
        self.latest_usable_before(key, None)
    }

    /// Latest usable observation observed at or before `before` (UTC secs).
    pub(crate) fn latest_usable_before(
        &self,
        key: &CollectionKey,
        before: Option<i64>,
    ) -> Result<Option<StoredObservation>> {
        self.inner.with_conn(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT o.id, o.status, o.native_status, o.observed_at, o.source_time, o.fresh_until, o.metadata, o.scan_id, c.kind, c.collection_key
                 FROM observations o JOIN collections c ON c.id = o.collection_id
                 WHERE c.collection_key = ?1 AND o.status IN ('success', 'not_found')
                     AND (?2 IS NULL OR o.observed_at <= ?2)
                 ORDER BY o.observed_at DESC, o.id DESC LIMIT 1",
            )?;
            let mut obs = stmt
                .query_row(
                    rusqlite::params![key.as_bytes().as_slice(), before],
                    obs_row_mapper(),
                )
                .optional()?;
            if let Some(o) = &mut obs {
                fill_links(conn, o)?;
            }
            Ok(obs)
})
    }

    /// Record that a scan consumed an observation with a given usage.
    pub(crate) fn record_usage(
        &self,
        scan_id: i64,
        observation_id: i64,
        usage: Usage,
    ) -> Result<()> {
        self.inner.with_conn(|conn| {
            conn.execute(
                "INSERT INTO scan_observations (scan_id, observation_id, usage) VALUES (?1, ?2, ?3)
                 ON CONFLICT(scan_id, observation_id) DO UPDATE SET usage = excluded.usage",
                rusqlite::params![scan_id, observation_id, usage.as_str()],
            )?;
            Ok(())
        })
    }

    /// Finish a scan (record `finished_at`).
    pub(crate) fn finish_scan(&self, scan_id: i64) -> Result<()> {
        self.inner.with_conn(|conn| {
            conn.execute(
                "UPDATE scans SET finished_at = ?1 WHERE id = ?2 AND finished_at IS NULL",
                rusqlite::params![now_secs(), scan_id],
            )?;
            Ok(())
        })
    }
}

/// Usage classification for scan consumption (the network cost of a run).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// This run collected the observation over the network (first ever, or
    /// nothing usable was stored).
    Collected,
    /// Served from the store; no network I/O in this run.
    Cached,
    /// This run re-collected (stale revalidation or forced refresh).
    Refreshed,
    /// Read from history (`Historical` requirement).
    Historical,
}

impl Usage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Usage::Collected => "collected",
            Usage::Cached => "cached",
            Usage::Refreshed => "refreshed",
            Usage::Historical => "historical",
        }
    }

    #[allow(clippy::should_implement_trait)] // inherent-by-choice; not a FromStr impl
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "collected" => Usage::Collected,
            "cached" => Usage::Cached,
            "refreshed" => Usage::Refreshed,
            "historical" => Usage::Historical,
            _ => return None,
        })
    }
}

/// Summary of a recorded scan.
#[derive(Clone, Debug)]
pub struct ScanSummary {
    pub id: i64,
    pub tool: String,
    pub invocation: serde_json::Value,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

/// Current time in UTC Unix seconds (the store's clock; consumers use it
/// for due math against facts read from a task list).
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

fn policy_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Policy> {
    Ok(Policy {
        kind: r.get(0)?,
        name: r.get(1)?,
        fresh_for: r
            .get::<_, Option<i64>>(2)?
            .map(|s| Duration::from_secs(s as u64)),
        allow_stale: r.get::<_, i64>(3)? != 0,
        stale_for: r
            .get::<_, Option<i64>>(4)?
            .map(|s| Duration::from_secs(s as u64)),
        ttl_min: r
            .get::<_, Option<i64>>(5)?
            .map(|s| Duration::from_secs(s as u64)),
        ttl_max: r
            .get::<_, Option<i64>>(6)?
            .map(|s| Duration::from_secs(s as u64)),
    })
}

fn meta_id(conn: &Connection, hash: &[u8; 32]) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT id FROM artifacts WHERE hash = ?1",
        rusqlite::params![hash.as_slice()],
        |r| r.get(0),
    )?)
}

fn obs_row_mapper() -> impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<StoredObservation> {
    |r| {
        let key_bytes: Vec<u8> = r.get(9)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&key_bytes);
        Ok(obs_from_row_impl(
            r.get(0)?,
            k,
            r.get(8)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn obs_from_row_impl(
    id: i64,
    key: [u8; 32],
    kind: String,
    status: String,
    native_status: Option<String>,
    observed_at: i64,
    source_time: Option<i64>,
    fresh_until: Option<i64>,
    metadata: String,
    scan_id: i64,
) -> StoredObservation {
    StoredObservation {
        id,
        key: CollectionKey(key),
        kind,
        status: ObservationStatus::from_str(&status)
            .unwrap_or_else(|| panic!("stored observation with unknown status `{status}`")),
        native_status,
        observed_at,
        source_time,
        fresh_until,
        metadata: serde_json::from_str(&metadata).unwrap_or(serde_json::Value::Null),
        artifacts: Vec::new(),
        scan_id,
    }
}

fn fill_links(conn: &Connection, obs: &mut StoredObservation) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.hash, a.size_uncompressed, a.compression, a.content_type, oa.role
         FROM observation_artifacts oa JOIN artifacts a ON a.id = oa.artifact_id
         WHERE oa.observation_id = ?1 ORDER BY oa.role",
    )?;
    let mut links = Vec::new();
    let rows = stmt.query_map(rusqlite::params![obs.id], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    for row in rows {
        let (hash, size_uncompressed, compression, content_type, role) = row?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        links.push(ArtifactLink {
            artifact: ArtifactMeta {
                hash: h,
                size_uncompressed: size_uncompressed as u64,
                compression: crate::evidence::observation::Compression::from_str(&compression)
                    .ok_or_else(|| Error::ArtifactUnknownCompression(compression.clone()))?,
                content_type,
            },
            role,
        });
    }
    obs.artifacts = links;
    Ok(())
}
