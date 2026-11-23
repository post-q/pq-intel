//! Domain-name normalization shared by all collectors.
//!
//! v1 normalizes hostnames for collection identity: ASCII lowercase, no
//! trailing dot, no leading wildcard label. When the monorepo consolidation
//! lands, this function is the single definition the tools' existing
//! normalization (pq-map's `cli::normalize_domain`, pq-pulse's identity
//! normalization for attribution) delegates to for *collection identity*;
//! entity-identity normalization (dropping `www.`, brand tokens) is
//! attribution-level logic and stays with the attribution tools.

/// Normalize a hostname for collection identity. Returns `None` for empty or
/// structurally invalid names (whitespace, empty labels).
///
/// Preserves punycode labels as-is (no IDNA in v1); callers pass
/// already-punycoded names from wire data.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let mut name = raw.trim();
    // Accept URL-ish input: take the host part.
    if let Some(rest) = name.strip_prefix("http://") {
        name = rest;
    } else if let Some(rest) = name.strip_prefix("https://") {
        name = rest;
    }
    let host_end = name.find('/').unwrap_or(name.len());
    name = &name[..host_end];
    let name = name.strip_suffix('.').unwrap_or(name);
    let name = name.strip_prefix("*.").unwrap_or(name);
    let lowered = name.to_ascii_lowercase();
    if lowered.is_empty() || lowered.contains(char::is_whitespace) {
        return None;
    }
    if lowered.split('.').any(|label| label.is_empty()) {
        return None;
    }
    Some(lowered)
}

/// Reverse-DNS query name for an IP address (`x.x.x.x.in-addr.arpa` /
/// nibble format for IPv6), as `dig -x` would query.
pub fn reverse_name(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for seg in v6.octets() {
                nibbles.push(seg >> 4);
                nibbles.push(seg & 0xf);
            }
            nibbles.reverse();
            let hexed: Vec<String> = nibbles.iter().map(|n| format!("{n:x}")).collect();
            format!("{}.ip6.arpa", hexed.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_trailing_dot_and_wildcard() {
        assert_eq!(
            normalize_domain("EXAMPLE.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("*.Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain(" https://Example.com/path ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
    }

    #[test]
    fn rejects_empty_and_invalid_names() {
        assert!(normalize_domain("").is_none());
        assert!(normalize_domain("  ").is_none());
        assert!(normalize_domain("exa mple.com").is_none());
        assert!(normalize_domain("example..com").is_none());
        assert!(normalize_domain(".example.com").is_none());
    }

    #[test]
    fn preserves_distinct_hostnames() {
        // www.example.com and example.com are different DNS identities.
        assert_ne!(
            normalize_domain("www.example.com").as_deref(),
            normalize_domain("example.com").as_deref()
        );
    }

    #[test]
    fn reverse_names_match_dig_dash_x() {
        assert_eq!(
            reverse_name("192.0.2.1".parse().unwrap()),
            "1.2.0.192.in-addr.arpa"
        );
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            reverse_name(v6),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }
}
