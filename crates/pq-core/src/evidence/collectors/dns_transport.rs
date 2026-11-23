//! Production DNS transports: UDP/TCP wire exchange (hickory-proto) and DoH
//! over the shared HTTP executor. Truncation (TC) on UDP falls back to TCP.

use super::dns::{DnsTransport, DnsTransportError, ResolverId};
use hickory_proto::op::Message;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// UDP + TCP transport with `dig`-equivalent semantics: 3-second query
/// timeout, TC → TCP retry.
pub struct UdpTcpDnsTransport {
    pub timeout: Duration,
}

impl UdpTcpDnsTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn udp(&self, addr: &str, wire: &[u8]) -> Result<Message, DnsTransportError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        let target: std::net::SocketAddr = addr.parse().map_err(|e| {
            DnsTransportError::Network(format!("bad resolver address `{addr}`: {e}"))
        })?;
        socket
            .send_to(wire, target)
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        let mut buf = [0u8; 65535];
        // Match the response to the query id; ignore late responses to stale
        // queries by re-reading (bounded).
        let expect_id = u16::from_be_bytes([wire[0], wire[1]]);
        for _ in 0..3 {
            let len = socket.recv_from(&mut buf).map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    DnsTransportError::Timeout(self.timeout)
                }
                _ => DnsTransportError::Network(e.to_string()),
            })?;
            let msg = Message::from_vec(&buf[..len.0])
                .map_err(|e| DnsTransportError::Malformed(e.to_string()))?;
            if msg.id() == expect_id {
                return Ok(msg);
            }
        }
        Err(DnsTransportError::Network(
            "no response matching the query id".into(),
        ))
    }

    fn tcp(&self, addr: &str, wire: &[u8]) -> Result<Message, DnsTransportError> {
        let target: std::net::SocketAddr = addr.parse().map_err(|e| {
            DnsTransportError::Network(format!("bad resolver address `{addr}`: {e}"))
        })?;
        let mut sock = TcpStream::connect_timeout(&target, self.timeout)
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        sock.write_all(&(wire.len() as u16).to_be_bytes())
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        sock.write_all(wire)
            .map_err(|e| DnsTransportError::Network(e.to_string()))?;
        let mut len_buf = [0u8; 2];
        sock.read_exact(&mut len_buf)
            .map_err(map_io(self.timeout))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        sock.read_exact(&mut buf).map_err(map_io(self.timeout))?;
        Message::from_vec(&buf).map_err(|e| DnsTransportError::Malformed(e.to_string()))
    }
}

fn map_io(timeout: Duration) -> impl Fn(std::io::Error) -> DnsTransportError {
    move |e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            DnsTransportError::Timeout(timeout)
        }
        _ => DnsTransportError::Network(e.to_string()),
    }
}

impl DnsTransport for UdpTcpDnsTransport {
    fn exchange(
        &self,
        resolver: &ResolverId,
        message: &Message,
    ) -> Result<Message, DnsTransportError> {
        let wire = message
            .to_vec()
            .map_err(|e| DnsTransportError::Malformed(e.to_string()))?;
        match resolver {
            ResolverId::System => {
                // The system resolver: first nameserver from
                // /etc/resolv.conf (re-read per exchange — resolv.conf can
                // change under DHCP). Same UDP semantics, TC → TCP retry.
                let addr = system_nameserver().map_err(DnsTransportError::Network)?;
                let response = self.udp(&addr, &wire)?;
                if response.truncated() {
                    self.tcp(&addr, &wire)
                } else {
                    Ok(response)
                }
            }
            ResolverId::Udp(addr) => {
                let response = self.udp(addr, &wire)?;
                if response.truncated() {
                    // TC → retry over TCP, as dig does.
                    self.tcp(addr, &wire)
                } else {
                    Ok(response)
                }
            }
            ResolverId::Tcp(addr) => self.tcp(addr, &wire),
            _ => Err(DnsTransportError::Network(format!(
                "transport does not serve {}",
                resolver.identity()
            ))),
        }
    }
}

/// First `nameserver` from /etc/resolv.conf, as `ip:port`. Pure on the
/// content for tests; the identity stays `system` in collection keys
/// regardless of which address serves it.
fn system_nameserver() -> Result<String, String> {
    let content = std::fs::read_to_string("/etc/resolv.conf")
        .map_err(|e| format!("system resolver: /etc/resolv.conf: {e}"))?;
    first_nameserver(&content)
        .ok_or_else(|| "system resolver: no nameserver in /etc/resolv.conf".to_string())
}

fn first_nameserver(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("nameserver")?;
        let rest = rest.trim();
        if rest.is_empty() || rest.starts_with('#') || rest.starts_with(';') {
            return None;
        }
        // Bare IP (resolv.conf has no port syntax); default port 53.
        // IPv6 must be bracketed to parse as a SocketAddr later.
        match rest.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(match ip {
                std::net::IpAddr::V4(_) => format!("{rest}:53"),
                std::net::IpAddr::V6(_) => format!("[{rest}]:53"),
            }),
            Err(_) => None,
        }
    })
}

/// DoH transport: DNS wire format POSTed to the DoH endpoint over the shared
/// HTTP executor (`application/dns-message`).
pub struct DohTransport {
    pub http: Arc<dyn crate::evidence::http::HttpExecutor>,
    pub timeout: Duration,
}

impl DnsTransport for DohTransport {
    fn exchange(
        &self,
        resolver: &ResolverId,
        message: &Message,
    ) -> Result<Message, DnsTransportError> {
        let ResolverId::DoH(url) = resolver else {
            return Err(DnsTransportError::Network(format!(
                "transport does not serve {}",
                resolver.identity()
            )));
        };
        let wire = message
            .to_vec()
            .map_err(|e| DnsTransportError::Malformed(e.to_string()))?;
        let request = crate::evidence::http::HttpRequest {
            url: url.clone(),
            method: crate::evidence::http::HttpMethod::Post,
            headers: vec![("content-type".into(), "application/dns-message".into())],
            body: Some(wire),
            timeout: self.timeout,
        };
        let response = self.http.execute(&request).map_err(|e| match e {
            crate::evidence::http::HttpExecError::Timeout(_) => {
                DnsTransportError::Timeout(self.timeout)
            }
            other => DnsTransportError::Network(other.to_string()),
        })?;
        if response.status != 200 {
            return Err(DnsTransportError::Network(format!(
                "DoH endpoint returned HTTP {}",
                response.status
            )));
        }
        Message::from_vec(&response.body).map_err(|e| DnsTransportError::Malformed(e.to_string()))
    }
}

/// Dispatches by resolver identity: UDP/TCP addresses to the direct
/// transport, DoH URLs over HTTP.
pub struct CompositeDnsTransport {
    pub direct: UdpTcpDnsTransport,
    pub doh: DohTransport,
}

impl CompositeDnsTransport {
    /// Production transport stack over the shared HTTP executor.
    pub fn production(
        http: Arc<dyn crate::evidence::http::HttpExecutor>,
        timeout: Duration,
    ) -> Self {
        Self {
            direct: UdpTcpDnsTransport::new(timeout),
            doh: DohTransport { http, timeout },
        }
    }
}

impl DnsTransport for CompositeDnsTransport {
    fn exchange(
        &self,
        resolver: &ResolverId,
        message: &Message,
    ) -> Result<Message, DnsTransportError> {
        match resolver {
            ResolverId::DoH(_) => self.doh.exchange(resolver, message),
            _ => self.direct.exchange(resolver, message),
        }
    }
}

/// Test utility (also used by the apps' offline tests): a canned DNS
/// transport serving pre-built responses keyed by query (name, type), with
/// call recording. Not part of the collection plane.
#[doc(hidden)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    pub struct CannedDnsTransport {
        pub responses: Vec<((String, u16), Message)>,
        pub calls: Mutex<Vec<String>>,
        /// When set, the nth call (counting down) fails with a timeout —
        /// scripted flakiness.
        pub fail_after: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    }

    impl CannedDnsTransport {
        pub fn new(responses: Vec<((String, u16), Message)>) -> Self {
            Self {
                responses,
                calls: Mutex::new(vec![]),
                fail_after: None,
            }
        }

        pub fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl DnsTransport for CannedDnsTransport {
        fn exchange(
            &self,
            _resolver: &ResolverId,
            message: &Message,
        ) -> Result<Message, DnsTransportError> {
            let q = message.queries().first().expect("query present");
            let key = (
                q.name()
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                q.query_type().into(),
            );
            self.calls.lock().unwrap().push(format!("{key:?}"));
            if let Some(countdown) = &self.fail_after {
                let n = countdown.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    return Err(DnsTransportError::Timeout(Duration::from_secs(3)));
                }
            }
            self.responses
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, m)| m.clone())
                .ok_or(DnsTransportError::Network(format!(
                    "no canned response for {key:?}"
                )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_nameserver_parse_takes_first_real_entry() {
        let conf = "# comment\noptions edns0\nnameserver 192.0.2.53\nnameserver 192.0.2.1\n";
        assert_eq!(first_nameserver(conf).as_deref(), Some("192.0.2.53:53"));
        // IPv6 is bracketed so the address parses as a SocketAddr later.
        assert_eq!(
            first_nameserver("nameserver 2001:db8::1\n").as_deref(),
            Some("[2001:db8::1]:53")
        );
        assert_eq!(first_nameserver("# only comments\n; also"), None);
        assert_eq!(first_nameserver(""), None);
        // A garbage nameserver line is skipped in favor of a later good one.
        assert_eq!(
            first_nameserver("nameserver not-an-ip\nnameserver 192.0.2.9\n").as_deref(),
            Some("192.0.2.9:53")
        );
    }
}
