# pq-intel

Externally observable infrastructure intelligence: a shared SQLite-backed
evidence store, and the tools that collect through it.

## Crates

- [`pq-core`](crates/pq-core) — the evidence store and its collectors (DNS
  and DoH, HTTP, TLS, Certificate Transparency, RDAP, RIPEstat, a
  conservative port sweep); append-only observations with full provenance,
  content-addressed artifacts, policy-driven cache reuse
- [`pq-map`](apps/pq-map) — domain service and cryptography discovery from
  Certificate Transparency and DNS
- [`pq-pulse`](apps/pq-pulse) — post-quantum TLS key-exchange probe with
  CDN/edge and vendor attribution of the endpoint

## The store

One SQLite database shared by every tool, at
`$XDG_DATA_HOME/pq-intel/evidence.db` (`~/.local/share/pq-intel` by
default). Observations are recorded append-only; a failure never overwrites
the last usable result, and a timeout is "unknown", never "nonexistent".
Cached data is reused only within its freshness policy — stale data is
revalidated on read. Every run records which observations it consumed, so
its network cost is auditable; nothing re-fetches what another tool already
collected.

## Build

Requires Rust (stable, >= 1.85). If needed, install via [rustup](https://rustup.rs)

```console
$ cargo build --release
```

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

Commits follow the [Conventional Commits](https://www.conventionalcommits.org)
specification; CI rejects non-conforming messages.

Releases are one version across the workspace: `cargo release <level>`
bumps it for every crate, cuts `pq-core-v…`/`pq-map-v…`/`pq-pulse-v…`
tags and pushes; each tag publishes its crate to
[crates.io](https://crates.io), tool tags additionally attach prebuilt
binaries to [GitHub Releases](https://github.com/post-q/pq-intel/releases).
The store's design specification is
[`specs/evidence-store-v1.md`](specs/evidence-store-v1.md).

## License

Licensed under the [European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
