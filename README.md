# pq-intel

Externally observable infrastructure intelligence, collected once and shared
by every tool: a SQLite-backed evidence and knowledge store with
content-addressed artifacts, plus the tools that collect through it.

## What is here

- **`crates/pq-core`** — the shared evidence store and its collectors.
  Collections identify repeatable requests by a canonical, versioned,
  content-hashed identity; observations record results append-only with full
  provenance (what was asked, which collector, which source answered, when,
  and the protocol-level status); raw evidence is preserved as
  SHA-256-content-addressed, compressed, deduplicated artifacts; per-source
  refresh policies decide when cached data may be reused — stale data is
  revalidated on read, blocking, and never silently presented as current.
  Collectors cover DNS (and DoH), HTTP, TLS, Certificate Transparency (the
  crt.sh JSON API and the certwatch PostgreSQL read path), RDAP, RIPEstat,
  and a conservative connect-sweep port scan. Failures are recorded, never
  overwrite the last usable result, and a timeout is "unknown", never
  "nonexistent".
- **`apps/pq-map`** — domain service and cryptography discovery from
  Certificate Transparency and DNS: CT snapshots, DNS sweeps, TLS probing,
  port sweeps, graph rendering. Fully store-backed.
- **`apps/pq-pulse`** — post-quantum TLS key-exchange probe with CDN/edge and
  vendor attribution of the endpoint. Store-backed.

## Using the store

The store lives at `$XDG_DATA_HOME/pq-intel/evidence.db`
(`~/.local/share/pq-intel` by default) with an `artifacts/` subtree beside
it. Every tool run opens a scan and records exactly which observations it
consumed, labeled by usage class (collected / cached / refreshed /
historical), so any past run can be reconstructed and its network cost
audited. All tools share one store: nothing re-fetches what another tool
already collected.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

Commits follow the Conventional Commits format. CI checks formatting,
clippy, tests, and commit messages.

Releases are tag-driven, one crate per tag: `pq-core-v…`, `pq-map-v…`,
`pq-pulse-v…` (tag must match the crate's `Cargo.toml` version). Every
tag publishes the crate to [crates.io](https://crates.io) (needs the
`CARGO_REGISTRY_TOKEN` repo secret); tool tags additionally attach
release binaries for three targets to a GitHub release. `pq-core` is a
dependency of both tools, so publish `pq-core` first when its version
changes — the tools' `pq-core = { version = … }` entries track it. The
design specification of the store is
[`specs/evidence-store-v1.md`](specs/evidence-store-v1.md).

## License

`pq-map`, `pq-pulse`, and `pq-core` are licensed under the
[European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
