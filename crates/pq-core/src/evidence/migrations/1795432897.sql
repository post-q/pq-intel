-- Epoch 1795432897 (2026-11-23): the collection plane. Entities, facts,
-- findings arrive in their own later migration. All timestamps are UTC
-- Unix seconds.
--
-- IF NOT EXISTS / OR IGNORE throughout: the command must also adopt
-- stores whose ledger predates the epoch renaming (they record versions
-- 1..4 and already carry this schema; every statement here is then a
-- no-op). On a fresh store the command builds exactly this schema.

CREATE TABLE IF NOT EXISTS refresh_policies (
    id             INTEGER PRIMARY KEY,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    fresh_for_secs INTEGER,             -- NULL = data stays fresh indefinitely (or is TTL-driven)
    allow_stale    INTEGER NOT NULL DEFAULT 0 CHECK (allow_stale IN (0, 1)),
    stale_for_secs INTEGER,             -- NULL = no staleness cap when allow_stale = 1
    ttl_min_secs   INTEGER,             -- DNS: lower clamp for source-provided TTLs
    ttl_max_secs   INTEGER,             -- DNS: upper clamp for source-provided TTLs
    UNIQUE (kind, name)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    tool        TEXT NOT NULL,
    invocation  TEXT NOT NULL DEFAULT '{}',  -- JSON: argv/parameters of the run
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS collections (
    id             INTEGER PRIMARY KEY,
    collection_key BLOB NOT NULL UNIQUE CHECK (length(collection_key) = 32),
    kind           TEXT NOT NULL,
    params         TEXT NOT NULL,       -- JSON; key-affecting parameters, secrets excluded
    policy_id      INTEGER REFERENCES refresh_policies(id)
);
CREATE INDEX IF NOT EXISTS idx_collections_kind ON collections(kind);

CREATE TABLE IF NOT EXISTS collection_state (
    collection_id   INTEGER PRIMARY KEY REFERENCES collections(id),
    latest_observation_id        INTEGER REFERENCES observations(id),  -- last attempt, any outcome
    next_refresh_at INTEGER,            -- maintained on write; consumed by nothing in v1 (no runner exists)
    lease_owner     TEXT,               -- reserved for cross-process leases; no lease logic in v1
    lease_until     INTEGER             -- reserved for cross-process leases; no lease logic in v1
);

CREATE TABLE IF NOT EXISTS observations (
    id            INTEGER PRIMARY KEY,
    collection_id INTEGER NOT NULL REFERENCES collections(id),
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    status        TEXT NOT NULL CHECK (status IN ('success', 'not_found', 'timeout', 'rate_limited', 'error')),
    native_status TEXT,                 -- protocol-level status, preserved verbatim (HTTP code, DNS rcode, ...)
    observed_at   INTEGER NOT NULL,     -- when we collected
    source_time   INTEGER,              -- when the source claims the data was measured
    fresh_until   INTEGER,              -- computed from policy + source metadata; never a claim of verified currency
    metadata      TEXT NOT NULL DEFAULT '{}'  -- JSON: small structured result (not bulk evidence)
);
CREATE INDEX IF NOT EXISTS idx_observations_collection_time ON observations(collection_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_observations_scan ON observations(scan_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id                INTEGER PRIMARY KEY,
    hash              BLOB NOT NULL UNIQUE CHECK (length(hash) = 32),  -- SHA-256 of the ORIGINAL uncompressed bytes
    size_uncompressed INTEGER NOT NULL,
    compression       TEXT NOT NULL DEFAULT 'zstd' CHECK (compression IN ('zstd', 'none')),
    content_type      TEXT NOT NULL,
    created_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS observation_artifacts (
    observation_id INTEGER NOT NULL REFERENCES observations(id),
    artifact_id    INTEGER NOT NULL REFERENCES artifacts(id),
    role           TEXT NOT NULL,       -- response_body, response_headers, redirect_chain, leaf_certificate, ...
    PRIMARY KEY (observation_id, artifact_id, role)
);
CREATE INDEX IF NOT EXISTS idx_observation_artifacts_artifact ON observation_artifacts(artifact_id);

CREATE TABLE IF NOT EXISTS scan_observations (
    scan_id        INTEGER NOT NULL REFERENCES scans(id),
    observation_id INTEGER NOT NULL REFERENCES observations(id),
    usage          TEXT NOT NULL CHECK (usage IN ('collected', 'cached', 'refreshed', 'historical')),
    PRIMARY KEY (scan_id, observation_id)
);
CREATE INDEX IF NOT EXISTS idx_scan_observations_observation ON scan_observations(observation_id);

-- Default refresh policies (long-form spec §9 table; all values configurable at
-- runtime through the policy API — this table is data, not code).
INSERT OR IGNORE INTO refresh_policies (kind, name, fresh_for_secs, allow_stale, stale_for_secs, ttl_min_secs, ttl_max_secs) VALUES
    ('ct',             'default',  NULL, 0, NULL, NULL, NULL),      -- CT results cached indefinitely
    ('x509',           'default',  NULL, 0, NULL, NULL, NULL),      -- X.509 certificate content cached indefinitely
    ('rdap',           'default',  604800, 0, NULL, NULL, NULL),   -- RDAP: 7 days (configurable 7-30)
    ('rdap-bootstrap', 'default',  NULL, 0, NULL, NULL, NULL),      -- IANA bootstrap files
    ('ripestat',       'default',  604800, 0, NULL, NULL, NULL),   -- RIPEstat generic endpoint: 7 days
    ('ripestat',       'network-info', 2592000, 0, NULL, NULL, NULL), -- registration-shaped: 30 days
    ('ripestat',       'routing-status', 604800, 0, NULL, NULL, NULL), -- routing-shaped: 7 days
    ('ripestat',       'historical', NULL, 0, NULL, NULL, NULL),      -- finalized-interval queries: indefinite
    ('dns',            'default',  NULL, 1, NULL, 30, 86400),     -- positive DNS: TTL-driven, clamped to [30s, 1d], stale reuse permitted
    ('dns',            'negative', NULL, 1, NULL, 60, 10800),     -- negative DNS: own policy (RFC 2308-ish), stale reuse permitted
    ('http',           'default',  86400, 0, NULL, NULL, NULL),   -- HTTP HTML-ish content: ~1 day
    ('tls',            'default',  86400, 0, NULL, NULL, NULL)    -- TLS endpoint observation: ~1 day
;
