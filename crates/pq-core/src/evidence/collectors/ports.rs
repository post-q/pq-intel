//! The ports collector: the conservative connect sweep as a first-class
//! collection (the trigger under which evidence-store-v1 deferred port
//! sweep).
//!
//! Identity: `endpoint + port-set fingerprint` — the canonical form hashes
//! the host and the sorted, deduplicated port list, so the same sweep asked
//! twice is one collection. The sweep is deliberately conservative: plain
//! TCP connects, one port at a time, paced (jittered delay between
//! connects), per-IP capped. `open`/`closed` are knowledge recorded as a
//! successful observation; an unresolvable host is an error observation,
//! never "nonexistent".
//!
//! Metadata shape (shared with tools that record richer sweeps — e.g.
//! pq-map records per-port TLS facts in the optional fields):
//! `{"host", "ips": [...], "results": [{"port", "state", "served"?,
//! "negotiated"?}]}`.

use crate::evidence::collector::{CollectionError, Collector};
use crate::evidence::error::{Error, Result};
use crate::evidence::key::{CanonicalWriter, CollectionRequest};
use crate::evidence::observation::{RawObservation, StoredObservation};
use crate::evidence::scan::Scan;
use crate::evidence::store::Store;
use crate::net::normalize_domain;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// A port-sweep request: which endpoint, which ports. Ports are sorted and
/// deduplicated; the sorted list IS the port-set fingerprint inside the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortsRequest {
    pub host: String,
    pub ports: Vec<u16>,
}

impl PortsRequest {
    pub fn new(host: &str, ports: &[u16]) -> Result<Self> {
        let host = normalize_domain(host)
            .ok_or_else(|| Error::Misuse(format!("invalid sweep host `{host}`")))?;
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { host, ports })
    }
}

impl CollectionRequest for PortsRequest {
    const KIND: &'static str = "ports";
    fn write_canonical(&self, w: &mut CanonicalWriter) {
        w.str_field("host", &self.host);
        w.str_field("port_set_version", "1");
        for port in &self.ports {
            w.u16_field("port", *port);
        }
    }
    fn stored_params(&self) -> serde_json::Value {
        serde_json::json!({ "host": self.host, "ports": self.ports })
    }
}

/// One swept (ip, port).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub ip: String,
    /// `open` | `closed` | `filtered` (timeout / unreachable).
    pub state: String,
    /// Richer per-port facts recorded by tools that probe open ports;
    /// `None` for the plain connect sweep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated: Option<serde_json::Value>,
}

/// Decoded ports observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortsObservation {
    pub host: String,
    /// Resolved addresses actually swept (capped).
    pub ips: Vec<String>,
    pub results: Vec<PortResult>,
}

/// The ports collector. Clones share nothing; pacing/timeout are per sweep.
#[derive(Clone)]
pub struct PortsCollector {
    pub connect_timeout: Duration,
    /// Minimum delay between successive connects (rate limit, jittered).
    pub pacing: Duration,
    /// Hard cap on distinct addresses swept per host.
    pub max_ips: usize,
}

impl Default for PortsCollector {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            pacing: Duration::from_millis(100),
            max_ips: 4,
        }
    }
}

/// Resolve `host` to the addresses to sweep (preserving resolver order,
/// capped at `max_ips`). IP-literal hosts resolve without DNS.
pub fn resolve_host(host: &str, max_ips: usize) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<IpAddr> = (host, 0u16).to_socket_addrs()?.map(|a| a.ip()).collect();
    let mut seen = std::collections::BTreeSet::new();
    Ok(addrs
        .into_iter()
        .filter(|ip| seen.insert(*ip))
        .take(max_ips)
        .collect())
}

/// Pure mapping: sweep outcome → raw observation. A completed sweep is a
/// success even when every port answered closed — closed is knowledge.
pub fn sweep_to_observation(host: &str, ips: &[IpAddr], results: &[PortResult]) -> RawObservation {
    let open = results.iter().filter(|r| r.state == "open").count();
    let mut raw = RawObservation::success(serde_json::json!({
        "host": host,
        "ips": ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        "results": results,
        "open": open,
    }));
    raw.native_status = Some(format!("tcp:{open}/{}-open", results.len()));
    raw
}

/// Decode stored metadata back into the typed view (works for observations
/// recorded by this collector and for richer tool-recorded sweeps).
pub fn observation_to_ports(obs: &StoredObservation) -> Result<PortsObservation> {
    serde_json::from_value(obs.metadata.clone()).map_err(|e| {
        Error::Misuse(format!(
            "ports observation {} has unusable metadata: {e}",
            obs.id
        ))
    })
}

/// Classify a connect outcome the way pq-map's sweep does: refusal is a
/// definitive `closed`; timeouts and unreachable networks are `filtered`
/// (the port's true state is unknown, never "open").
fn connect_state(ip: IpAddr, port: u16, timeout: Duration) -> &'static str {
    match TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout) {
        Ok(_) => "open",
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => "closed",
            _ => "filtered",
        },
    }
}

fn pacing(base: Duration) -> Duration {
    // 3/4 base + jitter in the last quarter: coarse rate limit that never
    // synchronizes across sweeps.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos() as u64)
        .unwrap_or(0);
    let base_ms = base.as_millis() as u64;
    let jitter = base_ms * 3 / 4 + nanos % (base_ms / 2).max(1);
    Duration::from_millis(jitter)
}

impl Collector for PortsCollector {
    type Request = PortsRequest;
    type Output = PortsObservation;

    fn collect(
        &self,
        _scan: &Scan,
        req: &PortsRequest,
        _prior: Option<&StoredObservation>,
    ) -> std::result::Result<RawObservation, CollectionError> {
        let ips = resolve_host(&req.host, self.max_ips).map_err(|e| CollectionError::Error {
            // Unresolvable target: recorded as an error observation ("unknown"),
            // never as a negative answer — the DNS collector owns the actual
            // DNS state.
            native: Some("dns:unresolved".into()),
            message: format!("{}: {e}", req.host),
        })?;
        if ips.is_empty() {
            return Err(CollectionError::Error {
                native: Some("dns:unresolved".into()),
                message: format!("{}: resolved to no addresses", req.host),
            });
        }

        let mut results = Vec::new();
        for ip in &ips {
            for port in &req.ports {
                results.push(PortResult {
                    port: *port,
                    ip: ip.to_string(),
                    state: connect_state(*ip, *port, self.connect_timeout).to_string(),
                    served: None,
                    negotiated: None,
                });
                std::thread::sleep(pacing(self.pacing));
            }
        }
        Ok(sweep_to_observation(&req.host, &ips, &results))
    }

    fn decode(&self, _store: &Store, obs: &StoredObservation) -> Result<PortsObservation> {
        observation_to_ports(obs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collector() -> PortsCollector {
        PortsCollector {
            connect_timeout: Duration::from_millis(300),
            pacing: Duration::from_millis(1), // tests: no throttling
            max_ips: 4,
        }
    }

    #[test]
    fn port_set_fingerprint_is_order_insensitive() {
        let a = PortsRequest::new("Example.com", &[8443, 9443, 4443]).unwrap();
        let b = PortsRequest::new("example.com.", &[9443, 4443, 8443, 9443]).unwrap();
        assert_eq!(a, b, "sorted, deduped, normalized host");
        assert_eq!(a.key(), b.key());
        let c = PortsRequest::new("example.com", &[8443, 9443]).unwrap();
        assert_ne!(
            a.key(),
            c.key(),
            "a different port set is a different collection"
        );
    }

    #[test]
    fn sweep_maps_states_and_counts_open() {
        let ips = vec!["127.0.0.1".parse().unwrap()];
        let results = vec![
            PortResult {
                port: 443,
                ip: "127.0.0.1".into(),
                state: "open".into(),
                served: None,
                negotiated: None,
            },
            PortResult {
                port: 8443,
                ip: "127.0.0.1".into(),
                state: "closed".into(),
                served: None,
                negotiated: None,
            },
            PortResult {
                port: 9443,
                ip: "127.0.0.1".into(),
                state: "filtered".into(),
                served: None,
                negotiated: None,
            },
        ];
        let raw = sweep_to_observation("example.com", &ips, &results);
        assert_eq!(
            raw.status,
            crate::evidence::observation::ObservationStatus::Success
        );
        assert_eq!(raw.metadata["open"], 1);
        assert_eq!(raw.metadata["results"].as_array().unwrap().len(), 3);
        assert_eq!(raw.native_status.as_deref(), Some("tcp:1/3-open"));
        let decoded: PortsObservation = serde_json::from_value(raw.metadata.clone()).unwrap();
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.results[0].port, 443);
    }

    #[test]
    fn richer_tool_recorded_metadata_decodes() {
        // pq-map-style record with per-port TLS facts decodes through the
        // same shape.
        let meta = serde_json::json!({
            "host": "mx.example.com",
            "ips": ["192.0.2.1"],
            "results": [
                {"port": 465, "ip": "192.0.2.1", "state": "open",
                 "served": {"subject": "mx.example.com"},
                 "negotiated": {"tls_version": "TLSv1.3"}}
            ]
        });
        let decoded: PortsObservation = serde_json::from_value(meta).unwrap();
        assert_eq!(decoded.results[0].state, "open");
        assert!(decoded.results[0].served.is_some());
    }

    #[test]
    fn connect_sweep_sees_open_and_closed_on_localhost() {
        // Real sockets, no external network: a live listener is `open`; a
        // just-released port refuses connections (`closed`).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed); // release: connect now gets refused (nothing rebinds it)

        let req = PortsRequest::new("127.0.0.1", &[open_port, closed_port]).unwrap();
        let scan = scan_stub();
        let raw = collector()
            .collect(&scan, &req, None)
            .unwrap_or_else(|e| panic!("sweep failed: {e:?}"));
        let obs = observation_to_ports(&stored_of(raw, &req)).unwrap();
        let by_port: std::collections::BTreeMap<u16, String> = obs
            .results
            .iter()
            .map(|r| (r.port, r.state.clone()))
            .collect();
        assert_eq!(by_port[&open_port], "open");
        assert_eq!(
            by_port[&closed_port], "closed",
            "refused = closed (definitive)"
        );
    }

    #[test]
    fn unresolvable_host_is_an_error_observation_not_not_found() {
        let req = PortsRequest::new("nxdomain.invalid", &[8443]).unwrap();
        let scan = scan_stub();
        let outcome = collector().collect(&scan, &req, None);
        let err = match outcome {
            Ok(_) => panic!("unresolvable host must not collect"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, CollectionError::Error { native: Some(n), .. } if n == "dns:unresolved"),
            "unresolved host is an error observation, got {err:?}"
        );
        assert_eq!(
            err.status(),
            crate::evidence::observation::ObservationStatus::Error
        );
    }

    // -- test plumbing: a scan handle without a store (the collector's
    // collect() never touches the store for this kind).
    fn scan_stub() -> Scan {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let scan = store
            .begin_scan("ports-test", serde_json::json!({}))
            .unwrap();
        std::mem::forget(dir); // lives for the process; test-scoped
        scan
    }

    fn stored_of(raw: RawObservation, req: &PortsRequest) -> StoredObservation {
        StoredObservation {
            id: 0,
            key: req.key(),
            kind: "ports".into(),
            status: raw.status,
            native_status: raw.native_status,
            observed_at: 0,
            source_time: None,
            fresh_until: None,
            metadata: raw.metadata,
            artifacts: vec![],
            scan_id: 0,
        }
    }
}
