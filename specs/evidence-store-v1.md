# Spec: Shared evidence and knowledge store (v1)

Labels: `ready-for-agent`
Date: 2026-11-21
Status: settled design (grilled 2026-11-20/21); supersedes the attached long-form spec for v1 scope. The long-form spec remains the long-horizon reference; every cut below is *deferred-with-trigger*, not deleted.

---

## Problem Statement

Three tools — `pq-map` (discovery via CT, DNS, certificates), `pq-pulse` (active probing of HTTP/TLS/mail), `pq-graph` (visualization) — each collect overlapping information about externally observable infrastructure, but share nothing. `pq-map` re-implements `pq-pulse`'s TLS result format by hand; each tool keeps its own ad-hoc cache files; collected evidence is either discarded or locked in per-tool directories. Every capability that needs the same information twice — vendor attribution from saved pages and DNS, monitoring a zone like `gov.pl` weekly, correlating CT output across tools — must re-fetch and re-parse everything from the network. There is no common place where "what did we already learn, from whom, and when" lives.

## Solution

A shared evidence and knowledge store, built as a Rust library module inside `pq-core` in the `pq-intel` monorepo, used by all tools on one machine.

- **Collections** identify repeatable requests (source, target, parameters) by a canonical, versioned, content-hashed identity.
- **Observations** record collection results append-only, with full provenance (what was asked, which collector, which source, when collected, when the source claims the data was measured, native protocol status).
- **Artifacts** preserve raw evidence (HTML, JSON responses, certificate DER) as compressed, SHA-256-content-addressed files, deduplicated globally.
- **Refresh policies** per collection type decide when cached data may be reused; stale data is revalidated **on read, blocking**, and is never silently presented as current.
- **Scans** record exactly which observations each tool run consumed, so any past run can be reconstructed.

Principle: *collect once, reuse across tools, retain evidence, avoid unnecessary network requests.* Single machine, SQLite + files, no cloud services, no distributed infrastructure. v1 ships the collection plane and migrates `pq-map` and `pq-pulse` onto it. Interpretation (entities, facts, findings, vendor attribution) is v2.

## User Stories

1. As an operator, I want all collected information retained in one shared store, so that no tool ever re-fetches what another tool already collected.
2. As an operator, I want raw evidence (HTML pages, JSON responses, certificates) preserved verbatim, so that I can re-analyze old scans without re-requesting anything.
3. As an operator, I want every stored record to identify what was requested, which collector ran, which source answered, and when, so that I can trace and trust every conclusion.
4. As an operator, I want a failed collection to never erase the last successful result, so that a flaky network or rate limit doesn't corrupt my knowledge base.
5. As an operator, I want a timeout recorded as "unknown", never as "nonexistent", so that a slow host isn't misrecorded as dead.
6. As an operator, I want to see whether data is fresh, stale, expired, or unavailable, so that I never mistake cached evidence for verified current state.
7. As an operator, I want per-source cache defaults (certificates and CT results indefinitely, RDAP days, DNS by TTL, HTTP/TLS roughly a day), so that crt.sh, RIPEstat, and RDAP providers are not hammered unnecessarily.
8. As an operator, I want to force a refresh of specific information regardless of cache state, so that I can get current state on demand for active assessment.
9. As an operator, I want IP-level RDAP and RIPEstat information reused across every hostname that resolves to the same IP, so that scanning a prefix costs one registration lookup, not one per host.
10. As an operator, I want DNS caching to respect TTLs while permitting stale reuse, so that DNS data is neither re-fetched constantly nor treated as invalid the moment a TTL lapses.
11. As an operator, I want negative DNS answers cached separately from positive ones, so that repeated NXDOMAINs don't generate repeat queries.
12. As an operator, I want HTTP revalidation via conditional requests, so that an unchanged page costs one 304 response instead of a full re-download.
13. As an operator, I want identical content deduplicated by hash, so that ten scans of an unchanged page store exactly one artifact.
14. As an operator, I want every tool run recorded together with exactly which observations it consumed, so that I can reconstruct later why a run concluded what it did.
15. As an operator, I want historical observations preserved after newer ones arrive, so that I can see how infrastructure changed over time.
16. As an operator, I want the store to run locally with no external paid APIs or cloud storage, so that the workflow stays private, free, and reproducible.
17. As an operator, I want scan usage classified (collected / cached / refreshed / historical), so that I can see the network cost of each run.
18. As an operator, I want native protocol statuses (HTTP status codes, DNS rcodes, RDAP statuses, TLS failures) preserved alongside normalized statuses, so that protocol nuance is never lost to normalization.
19. As an operator, I want a refresh-due marker maintained per collection, so that a future scheduled runner can process due refreshes without a schema change.
20. As a developer, I want one canonical Rust storage API shared by all tools, so that no tool hand-rolls its own persistence.
21. As a developer, I want structured Rust types for collections, observations, and artifacts, so that consumers cannot misread evidence shapes as arbitrary JSON.
22. As a developer, I want collection identity derived from a deterministic, versioned canonicalization of the request, so that equivalent requests deduplicate and canonicalization changes never silently alias old data.
23. As a developer, I want credentials and secrets excluded from collection keys and stored parameters, so that nothing sensitive leaks into the database.
24. As a developer, I want concurrent identical requests single-flighted within a process, so that parallel work never double-fetches.
25. As a developer, I want versioned, explicit schema migrations, so that store upgrades are deterministic and reversible to reason about.
26. As a developer, I want artifact writes to be crash-safe, so that an interrupted run never leaves phantom or corrupt evidence.
27. As a developer, I want DNS, HTTP, TLS, CT, RDAP, and RIPEstat collection unified as collectors over the store, so that `pq-map` and `pq-pulse` stop maintaining parallel probing code.
28. As a developer, I want `pq-pulse`'s shell-out to `dig` replaced by the shared DNS collector, so that DNS behavior is consistent, identity-aware, and testable.
29. As a developer, I want `pq-map`'s TLS output to stop hand-mimicking `pq-pulse`'s JSON format, so that there is exactly one definition of a TLS observation.
30. As a developer, I want refresh policies stored as configurable data rather than code, so that tuning cache behavior never requires a rebuild.
31. As `pq-map`, I want to read and write the shared store instead of my private cache directory, so that my results become persistent and reusable by other tools.
32. As `pq-pulse`, I want my observations recorded in the shared store, so that `pq-map` and future attribution reuse them without re-probing.
33. As future `pq-attribution`, I want observations with complete provenance available in the store, so that vendor verdicts are traceable to evidence.
34. As future `pq-graph`, I want the knowledge underneath `graph.json` to come from the shared store, so that visualization keeps working unchanged while the store evolves.
35. As a developer, I want domain-name normalization reused from the existing core normalization logic, so that entity identity is consistent across all collectors.

## Implementation Decisions

**Home and shape**

- The store is a module inside `pq-core` in the `pq-intel` monorepo (prerequisite: the monorepo consolidation is a separate mechanical step; this spec assumes the module location). It must not require consumers to touch probing concerns.
- Dependency direction: apps (`pq-map`, `pq-pulse`) depend on `pq-core`; `pq-attribution` (v2) depends on `pq-core` and reads observations; `pq-graph` is untouched JS.
- Scale target is thousands of observations. Nothing in v1 exists to serve 10M/100M: no packed/object backends, no compaction, no integrity-check scheduling. SQLite handles this scale trivially.

**Schema (v1 migration creates exactly these tables)**

- `refresh_policies`, `collections`, `collection_state`, `observations`, `artifacts`, `observation_artifacts`, `scans`, `scan_observations` — as specified in the long-form spec §§4.1–5, with constraints and the documented indexes.
- Entities, facts, fact_evidence, fact_assertions, findings, finding_dependencies are **not** in the v1 migration; they arrive in a v2 migration.
- PRAGMAs: `foreign_keys = ON`, `journal_mode = WAL`, plus a busy timeout for multi-process CLI access. All timestamps are UTC Unix seconds.
- `collections.collection_key`: SHA-256 over a canonical representation of the request identity. A canonicalization version constant is prefixed into the digest input, so changing canonicalization yields new identities rather than aliasing old data. Parameters that affect the response are included (TLS: endpoint, SNI, ALPN, client config; DNS: name, type, class, resolver identity; HTTP: URL, method, relevant headers, body identity; RIPEstat: endpoint + resource + parameters). Credentials and secrets are never stored in keys or plaintext parameters.
- `collection_state` keeps `lease_owner`/`lease_until` columns in the schema, but v1 implements no lease logic (reserved for when parallel scheduled runs actually collide).
- `observations.status` is a closed set: `success`, `not_found`, `timeout`, `rate_limited`, `error`. `native_status` preserves the protocol-level status separately. `source_time` (source-claimed measurement time) is distinct from `observed_at`. A failed observation never overwrites the last successful one.
- `fresh_until` is computed from the collection policy plus relevant source metadata (e.g., DNS TTL); it is never a claim of verified currency.
- `scan_observations.usage` ∈ `collected | cached | refreshed | historical`. Every tool invocation creates a scan row.

**Freshness and revalidation**

```text
// from the long-form spec (§9.5); adopted verbatim as the API contract
enum FreshnessRequirement { Cached, MaxAge(Duration), Refresh, Historical { at: DateTime<Utc> } }
enum DataStatus { Fresh, Stale, Expired, Unavailable }
```

- Revalidation is **on-read and blocking**: a consumer asking for fresher-than-cached data causes the collector to run synchronously before the read returns. `stale_while_revalidate` policy flags are reserved for the future runner era.
- `collection_state.next_refresh_at` is maintained on every read/write but consumed by nothing in v1 (no runner exists).
- Policy defaults follow the long-form spec §9 table (CT and X.509 indefinite; RDAP 7–30 days; RIPEstat per-endpoint, registration vs. routing distinguished; DNS TTL-respecting with separate negative caching and stale permission; HTTP HTML 24h–days; TLS 24h). All values configurable.
- HTTP collector implements conditional requests (`If-None-Match` / `If-Modified-Since`); a 304 confirms the cached representation without creating a duplicate body artifact. Redirect chains and validators are preserved.

**Artifacts**

- Identity: SHA-256 of the **original uncompressed bytes**. Compression (Zstandard) metadata stored separately from content type.
- Backend: filesystem (content files keyed by hash) with catalog rows in SQLite. The `ArtifactStore` trait is defined now; SQLite-blob, packed, and object backends are deferred.
- Crash-safe write sequence: write to temp → verify hash → atomically publish → commit DB reference. Interrupted writes and orphan artifacts must be tolerated (GC is out of scope, so orphans may persist).
- One observation may reference multiple artifacts via roles (`response_body`, `response_headers`, `redirect_chain`, `leaf_certificate`, `intermediate_certificate`, `rdap_response`, …). Not every observation produces an artifact; small structured results live in observation metadata.

**Concurrency**

- In-process single-flight per collection identity: duplicate concurrent requests share one in-flight collection. No cross-process leases in v1.

**Collectors (v1 = every collection path that exists today, unified)**

- **DNS**: hickory-based collector; `pq-pulse`'s `dig` shell-out is removed. Resolver identity is part of the collection key. Different resolvers' answers are not treated as contradictions; complete RRsets are preserved.
- **DoH**: a DNS-kind observation using HTTP as transport (distinct source identity), not an HTTP observation.
- **HTTP**: URL-targeted; status, headers, body, redirect chain; conditional revalidation as above.
- **TLS**: endpoint-targeted; protocol, cipher suite, key exchange, served chain; SNI/ALPN in the key. One definition of the TLS observation replaces both tools' formats (`pq-map`'s "pq-pulse-compatible presentation" hack dies).
- **CT**: crt.sh certwatch lookups (Postgres read path kept thin, with its row→observation mapping extracted as a pure function; HTTP fallback goes through the shared HTTP executor). Cached indefinitely.
- **RDAP**: by canonical lookup target and provider; original JSON preserved as artifact; normalized extraction deferred to v2.
- **RIPEstat**: per-endpoint identities (`ripestat.network-info`, `ripestat.routing-status`, …) with per-endpoint policies; historical (finalized-interval) queries cached indefinitely.
- Domain/hostname normalization reuses `pq-core`'s existing normalization logic.
- *(Amended 2026-11-23, user decision: the no-reinvented-wheels line is enforced — all certwatch semantics (`ctdate`, name/coverage/serial/validity math), X.509 naming (OID tables, canonical signature/key names, cipher suites), and port presets live in `pq-core` (`evidence::collectors::ct`, `x509`, `collectors::ports::presets`). pq-map and pq-pulse keep only presentation and their own decision models; edge binaries never copy core data tables or policy. Same line, same day, applied to the rest of the surface: the OpenSSL legacy TLS transport (`collectors::openssl_tls`, feature `openssl-tls` — TLS 1.0/1.1, `SECLEVEL=0`) produces the shared `TlsSessionFacts` beside the rustls connector; DNS presentation-format parsing (`parse_mx/srv/svcb_presentation`) and the well-known SRV sweep vocabulary live in `collectors::dns`; the `in_domain` host-boundary check in `net`. Edge binaries keep orchestration, display labels, and model mapping only.)*

**Cutover**

- Hard cutover: `pq-map` and `pq-pulse` become exclusively store-backed in v1. No import of legacy caches (`~/.cache/pq-map`, `pq-pulse`'s tmp files); the first post-cutover runs re-collect once from the network; old cache directories become inert.
- Store location defaults to `~/.local/share/pq-intel/evidence.db` with XDG environment overrides.

**Repo-level decisions recorded from the prior session** (context, not this spec's deliverables): monorepo `post-q/pq-intel`, branch `main`, locked workspace versioning starting at 0.8.0, single release train, old repos left unarchived.

## Testing Decisions

A good test exercises **externally observable behavior** through a public interface — never internals, table layout, or private call graphs. Every test is deterministic, isolated (throwaway temp directories, no live network), and safe to run in the full suite.

**Pyramid** — most tests at the bottom, fewest at the top:

1. **Unit tests (the bulk):** the pure mappings (TLS session-state → observation, CT rows → observation, request → canonical collection key) and policy math (`fresh_until`, TTL clamping). No I/O, no store, inline `#[cfg(test)]` modules next to the code.
2. **Store-API integration tests (the second tier):** the ten v1 invariants, exercised through the evidence module's public API against a real SQLite database in a temp directory. Real engine, no mocks.
3. **Acceptance (smoke, count in low single digits):** CLI-level only, proving the v1 acceptance: a run completes from cache when allowed; an immediate second run performs zero network requests.

**Data injection** — fixture strategy by tier:

- Default: **seed through the public API** (ingest observations, put artifacts) using small Rust constructor helpers. Fixtures stay valid across schema refactors because they go through the same ingestion path as production; no raw SQL dumps.
- File fixtures where data is bulky or real-world-shaped (canned HTTP responses, DER certificate chains, crt.sh payloads): embedded at compile time and deserialized into the typed structs — the house pattern already exists (`pq-pulse`'s fixture-driven decision-model integration test, `pq-map`'s test data and example graph JSON).
- Unit-tier tests construct their inputs as plain struct literals; no fixtures, no helpers beyond the module.
- Shared helpers for the integration tier live in a common module under the integration-test directory, not duplicated per test file.

Seams (the points where tests attach, in plain terms):

1. **Primary seam — the evidence module's public API.** Opened against a temp directory, all v1 invariants are observable through normal use: cache reuse across consumers; stale → blocking revalidate; failed refresh preserves the last success; freshness labels (fresh/stale/expired/unavailable) never lie; provenance fields survive ingestion; artifact dedup and crash-safety (kill the write sequence mid-way); scan usage recording; collection-key equivalence for canonicalized-equal requests and inequivalence when parameters differ; secrets absent from keys.
2. **Network-boundary seams (the only new seams, forced by "no live network in tests"):** a canned HTTP executor covers the five HTTP-speaking collectors (HTTP, DoH, RDAP, RIPEstat, CT-HTTP-fallback) — including conditional-request (ETag/304) behavior; a canned DNS transport covers TTL semantics, negative caching, and stale-permission behavior. Production impls (real HTTP client, hickory) sit behind the same traits.
3. **Pure-function seams (no new seam):** TLS session-state → observation mapping and the CT Postgres row → observation mapping are plain functions tested directly.
4. **Acceptance seam (highest, smoke-only):** the `pq-map` and `pq-pulse` CLIs run against a temp store with canned transports. A small number of tests prove the v1 acceptance: a run completes from cache when allowed, and an immediate second run performs **zero** network requests.

Prior art: `pq-pulse`'s offline integration test of the decision model (fixture-driven, no network) sets the house style; `pq-map` uses inline unit tests. New tests live with `pq-core` (integration tests for the store seam; unit tests for pure mappings; end-to-end smoke tests for the CLI acceptance).

## Out of Scope

- **Entities, facts, extractors, findings, attribution** — v2 (temporal-first invalidation: a finding goes stale when a dependency observation is newer than its calculation; typed/semantic dependency tracking only when false-stale rate demands it). The v2 schema migration adds those tables.
- **Retention / GC** — no artifact or observation pruning in v1. Trigger: bulk zone-wide scheduled collection (e.g., weekly `gov.pl` runs) becoming real.
- **Cross-process leases** — columns reserved, logic unimplemented. Trigger: parallel scheduled runs actually colliding.
- **SQLite-blob, packed, or object artifact backends** — filesystem backend only; the `ArtifactStore` trait is the seam for later backends.
- **Rate limiting / source politeness** — beyond recording `rate_limited` status. Deferred decision; must be resolved before any bulk scheduled collection (crt.sh Postgres and RIPEstat will notice abuse).
- **Import of legacy caches** — hard cutover instead; old cache files are neither read nor migrated.
- **Observation history compaction and semantic content hashes** — raw observations retained; grouping of repeated identical observations is a later optimization.
- **Distributed storage, PostgreSQL, cloud services, external paid APIs** — permanently out unless a measurable requirement appears.
- **The monorepo consolidation mechanics** (filter-repo history merge, CI wiring, release train) — prerequisite infrastructure, tracked separately.
- **`pq-graph` changes** — it keeps reading `graph.json`; the store feeds `pq-map`'s rendering, invisibly to the JS side.

## Further Notes

- The long-form spec (§§1–15) remains the architectural reference for v2+ (facts/findings model, invalidation semantics, scalability table). Where v1 cuts conflict with it (scale tiers, leases, SWR runner, import), this spec wins for v1 and the cut items carry their triggers.
- Deferred decisions that will need their own rounds before v2: rate-limiting strategy per source; findings invalidation granularity; whether `pq-attrib` (batch CLI, existing Fabryka/System One decision client) lands early-v2 reading observations directly, or after the facts layer.
- Vocabulary note: the terms *collection, observation, artifact, fact, finding, freshness, validity, retention* are defined by the long-form spec §2 and should seed a `GLOSSARY.md` (none exists yet) when the domain-modeling skill runs. ADR candidates from this session: on-read blocking revalidation; filesystem-first artifacts; store as `pq-core` module rather than its own crate.
- `/setup-matt-pocock-skills` has not been run; per the user's choice this spec uses a plain local file under `specs/` with the triage label recorded in the header instead of a tracker-attached label.
