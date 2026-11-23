use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{Local, Utc};
use futures::StreamExt;

use crate::config::Config;
use crate::discover::{ct, dns, fetch, resolve};
use crate::model::{
    CtStats, DnsRef, DnsStatus, DomainState, Endpoint, Host, Origins, PortScan, ProbeStatus,
    ScanState,
};
use pq_core::evidence::collectors::ct::{future_valid, is_wildcard};
use pq_core::evidence::collectors::ports::presets::{PortKind, PORT_CAP, ports_for_host};

const TLS_PORT: u16 = 443;

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub refresh: bool,
    pub probe: bool,
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ct(#[from] fetch::Error),
    #[error("task join failed")]
    Join,
}

pub async fn collect(
    domain: &str,
    cfg: &Config,
    opts: &Options,
    ev: &crate::store::MapEvidence,
) -> Result<DomainState, Error> {
    // 1. CT snapshot (store-backed: certwatch DB → crt.sh → last success).
    let outcome = fetch::obtain(domain, cfg, opts.refresh, ev).await?;
    let certs = outcome.certs;
    let ct_stats = ct_stats(&certs);

    // 2. DNS: SRV sweep + SVCB/HTTPS on the apex (store-backed collections).
    let discovery = dns::discover(domain, ev).await;

    // 3. Host set: concrete CT names ∪ apex ∪ in-domain SRV targets.
    let mut hosts: BTreeMap<String, Host> = BTreeMap::new();
    for cert in certs.values().filter(|c| c.currently_valid) {
        for name in &cert.identities {
            if !is_wildcard(name) {
                let host = hosts.entry(name.clone()).or_default();
                host.name = name.clone();
                host.origins.insert(Origins::CT);
            }
        }
    }
    let apex = hosts.entry(domain.to_string()).or_default();
    apex.name = domain.to_string();
    apex.origins.insert(Origins::APEX);
    for rec in &discovery.srv {
        if pq_core::net::in_domain(&rec.target, domain) {
            let host = hosts.entry(rec.target.clone()).or_default();
            host.name = rec.target.clone();
            host.origins.insert(Origins::DNS);
            host.dns_refs.push(DnsRef::Srv {
                service: rec.service.clone(),
            });
        }
    }
    for rec in &discovery.mx {
        let host = hosts.entry(rec.target.clone()).or_default();
        host.name = rec.target.clone();
        host.origins.insert(Origins::DNS);
    }

    // 4. CT coverage per host (exact / wildcard refs).
    for host in hosts.values_mut() {
        host.ct_refs = ct::cert_refs(&certs, &host.name);
    }

    // 5. Resolve every host concurrently, capturing the response status.
    //    Store-backed A/AAAA collections, run off the runtime.
    let resolution: Vec<(String, Option<IpAddr>, DnsStatus)> =
        futures::stream::iter(hosts.keys().map(|name| {
            let ev = ev.clone();
            let name = name.clone();
            async move {
                let (ip, status) = tokio::task::spawn_blocking({
                    let ev = ev.clone();
                    let name = name.clone();
                    move || resolve::resolve_status(&ev, &name)
                })
                .await
                .unwrap_or((None, DnsStatus::Other));
                (name, ip, status)
            }
        }))
        .buffer_unordered(cfg.dns_concurrency)
        .collect()
        .await;

    for (name, ip, status) in &resolution {
        let host = hosts.get_mut(name).expect("host from map");
        host.resolves = Some(ip.is_some());
        host.dns_status = Some(*status);
    }

    // 6. Probe resolving hosts. Every probe is a store-backed TLS
    //    collection (blocking pool); failures are observations like any
    //    other — no file cache sits in front of the store.
    if opts.probe {
        let endpoints: Vec<(String, Endpoint)> =
            futures::stream::iter(resolution.iter().map(|(name, ip, _)| {
                let name = name.clone();
                async move {
                    let endpoint = if ip.is_some() {
                        crate::probe::probe_one(&name, *ip, TLS_PORT, cfg, ev).await
                    } else {
                        Endpoint::failed(ProbeStatus::DnsFailure)
                    };
                    (name, endpoint)
                }
            }))
            .buffer_unordered(cfg.probe_concurrency)
            .collect()
            .await;

        for (name, endpoint) in endpoints {
            if let Some(host) = hosts.get_mut(&name) {
                host.endpoint = Some(endpoint);
            }
        }
    }

    if opts.probe
        && let Some(explicit_ports) = &opts.ports
    {
        let mx_names: Vec<String> = discovery.mx.iter().map(|rec| rec.target.clone()).collect();

        let mut targets: Vec<(String, IpAddr)> = resolution
            .iter()
            .filter(|(name, ip, _)| {
                ip.is_some()
                    && hosts
                        .get(name)
                        .and_then(|h| h.endpoint.as_ref())
                        .is_some_and(|e| {
                            matches!(
                                e.status,
                                ProbeStatus::TcpRefused
                                    | ProbeStatus::TcpUnreachable
                                    | ProbeStatus::Timeout { .. }
                            )
                        })
            })
            .filter_map(|(name, ip, _)| ip.map(|ip| (name.clone(), ip)))
            .collect();

        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos() as u64)
            .unwrap_or(1);
        for i in (1..targets.len()).rev() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (seed >> 33) as usize % (i + 1);
            targets.swap(i, j);
        }

        let mx_targets = std::sync::Arc::new(
            mx_names
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<String>>(),
        );
        // The SHARED ports collector (pq-core), tuned by map's sweep config:
        // one scanner for every consumer, store-visible evidence only.
        let ports_reader = pq_core::evidence::collectors::ports::PortsCollector {
            connect_timeout: cfg.sweep_connect_timeout,
            pacing: std::time::Duration::from_millis(cfg.sweep_delay_ms),
            ..Default::default()
        };
        // (name, scans, swept_fresh)
        let sweep_results: Vec<(String, Vec<PortScan>, bool)> =
            futures::stream::iter(targets.into_iter().map(|(name, ip)| {
                let mx_targets = std::sync::Arc::clone(&mx_targets);
                let ev = ev.clone();
                let ports_reader = ports_reader.clone();
                async move {
                    let _ = ip;
                    let is_mx = mx_targets.contains(&name);
                    let ports: Vec<(u16, PortKind)> = match explicit_ports {
                        list if list.is_empty() => ports_for_host(&name, &cfg.probe_ports, is_mx),
                        list => list
                            .iter()
                            .take(PORT_CAP)
                            .map(|p| (*p, PortKind::DirectTls))
                            .collect(),
                    };
                    let port_list: Vec<u16> = ports.iter().map(|(p, _)| *p).collect();

                    // One collection keyed by endpoint + port set, driven by
                    // the shared collector on the blocking pool (host
                    // fan-out stays async). MaxAge is the sweep TTL: the
                    // store serves the last sweep while it is fresh enough
                    // and runs the paced connect sweep only when nothing
                    // fresh is stored — the store's own freshness handling,
                    // no snapshot cache in front of it.
                    let swept_fresh = |usage: pq_core::evidence::Usage| {
                        !matches!(usage, pq_core::evidence::Usage::Cached)
                    };
                    let req =
                        pq_core::evidence::collectors::ports::PortsRequest::new(&name, &port_list);
                    match &req {
                        Ok(req) => {
                            let sweep_ttl = cfg.sweep_ttl;
                            let req = req.clone();
                            match tokio::task::spawn_blocking(move || {
                                ev.scan.collect(
                                    &ports_reader,
                                    req,
                                    pq_core::evidence::FreshnessRequirement::MaxAge(
                                        std::time::Duration::from_secs(sweep_ttl),
                                    ),
                                )
                            })
                            .await
                            {
                                Ok(Ok(out)) => {
                                    let scans = match out
                                        .observation
                                        .as_ref()
                                        .map(ports_scans_from_observation)
                                    {
                                        Some(Ok(scans)) => scans,
                                        Some(Err(e)) => {
                                            eprintln!("ports: {name}: decode: {e}");
                                            vec![]
                                        }
                                        None => vec![],
                                    };
                                    let fresh = swept_fresh(out.usage);
                                    (name, scans, fresh)
                                }
                                Ok(Err(e)) => {
                                    eprintln!("ports: {name}: {e}");
                                    (name, vec![], false)
                                }
                                Err(e) => {
                                    eprintln!("ports: {name}: join: {e}");
                                    (name, vec![], false)
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("ports: {name}: bad request: {e}");
                            (name, vec![], false)
                        }
                    }
                }
            }))
            .buffer_unordered(cfg.sweep_concurrency)
            .collect()
            .await;

        let (mut fresh_sweeps, mut cached_sweeps, mut open_hosts) = (0usize, 0usize, 0usize);
        for (name, scans, swept) in sweep_results {
            if swept {
                fresh_sweeps += scans.len();
            } else {
                cached_sweeps += scans.len();
            }
            if scans.iter().any(|s| s.state == ScanState::Open) {
                open_hosts += 1;
            }
            if let Some(host) = hosts.get_mut(&name) {
                host.ports = scans.clone();
            }
        }

        eprintln!(
            "ports: {cached_sweeps} cached, {fresh_sweeps} swept fresh, {open_hosts} with open ports"
        );
    }

    // 7. Correlate served certificates with CT; propagate signature facts.
    let mut certs = certs;
    for host in hosts.values() {
        let served_certs = host
            .endpoint
            .as_ref()
            .and_then(|e| e.served.as_ref())
            .into_iter()
            .chain(host.ports.iter().filter_map(|s| s.served.as_ref()));
        for served in served_certs {
            if let Some(cert) = certs.get_mut(&served.serial) {
                cert.served_live = true;
                if cert.cert_signature.is_none() {
                    cert.cert_signature = served.cert_signature.clone();
                }
                if cert.pubkey_alg.is_none() {
                    cert.pubkey_alg = served.pubkey_alg.clone();
                }
                if cert.sig_alg.is_none() {
                    cert.sig_alg = served.sig_alg.clone();
                }
            }
        }
    }
    for host in hosts.values_mut() {
        if let Some(endpoint) = &mut host.endpoint {
            if let Some(served) = &endpoint.served {
                endpoint.served_not_in_ct = !certs.contains_key(&served.serial);
            }
        }
    }

    Ok(DomainState {
        domain: domain.to_string(),
        checked_at: Local::now(),
        provenance: outcome.provenance,
        ct_stats,
        certs,
        hosts,
        srv: discovery.srv,
        https: discovery.https,
        mx: discovery.mx,
    })
}

/// Ports metadata ↔ pq-map's PortScan model. The wire shape has ONE owner
/// (`pq_core::evidence::collectors::ports` — `PortResult`,
/// `sweep_to_observation`, `observation_to_ports`); these are thin
/// model-mapping shims, not a second encoding.
///
/// `served`/`negotiated` are optional in both directions: a plain connect
/// sweep carries only port states, a richer recorded sweep adds the TLS
/// facts its tool probed.
fn ports_scans_from_observation(
    obs: &pq_core::evidence::StoredObservation,
) -> Result<Vec<PortScan>, pq_core::evidence::Error> {
    let data = pq_core::evidence::collectors::ports::observation_to_ports(obs)?;
    let observed_at = obs.observed_at_time();
    Ok(data
        .results
        .into_iter()
        .map(|r| PortScan {
            port: r.port,
            state: match r.state.as_str() {
                "open" => ScanState::Open,
                "closed" => ScanState::Closed,
                _ => ScanState::Filtered,
            },
            served: r.served.and_then(|v| serde_json::from_value(v).ok()),
            negotiated: r.negotiated.and_then(|v| serde_json::from_value(v).ok()),
            observed_at,
        })
        .collect())
}

fn ct_stats(certs: &BTreeMap<String, crate::model::Certificate>) -> CtStats {
    let now = Utc::now();
    let mut stats = CtStats {
        rows: certs.len(),
        valid: 0,
        future: 0,
    };
    for cert in certs.values() {
        if cert.currently_valid {
            stats.valid += 1;
        } else if future_valid(cert.not_before, now) {
            stats.future += 1;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Certificate;
    use pq_core::evidence::collectors::ct::currently_valid;

    fn cert(serial: &str, nb: &str, na: &str) -> Certificate {
        let parse = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&Utc)
        };
        let (nb, na) = (Some(parse(nb)), Some(parse(na)));
        Certificate {
            serial: serial.to_string(),
            in_ct: true,
            served_live: false,
            currently_valid: currently_valid(nb, na, Utc::now()),
            ct_ids: vec![1],
            common_name: None,
            identities: vec![],
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
        }
    }

    #[test]
    fn ct_stats_counts_grouped_certs() {
        let mut certs = BTreeMap::new();
        certs.insert(
            "aa11".to_string(),
            cert("aa11", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
        );
        certs.insert(
            "bb22".to_string(),
            cert("bb22", "2027-06-01T00:00:00Z", "2028-01-01T00:00:00Z"),
        );
        certs.insert(
            "cc33".to_string(),
            cert("cc33", "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
        );
        let stats = ct_stats(&certs);
        assert_eq!(stats.rows, 3);
        assert_eq!(stats.valid, 1);
        assert_eq!(stats.future, 1);
    }
}
