//! Map's sweep POLICY: which ports a host family gets (port presets and
//! service-kind classification). The sweep itself — the paced connect
//! sweep — is the shared `pq_core::evidence::collectors::ports` collector;
//! pq-map drives it from its collect path and records the observation
//! through the evidence store like every other collection.

/// Service-kind classification for preset ports: a DirectTls port speaks
/// TLS on connect; a StartTls port upgrades in-band first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    DirectTls,
    StartTls,
}

const GENERIC_WEB: &[(u16, PortKind)] = &[
    (8443, PortKind::DirectTls),
    (9443, PortKind::DirectTls),
    (4443, PortKind::DirectTls),
    (8843, PortKind::DirectTls),
    (10000, PortKind::DirectTls),
];

pub const PORT_CAP: usize = 5;

pub fn ports_for_host(name: &str, generic_override: &[u16], is_mx: bool) -> Vec<(u16, PortKind)> {
    let label = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    let table: &[(u16, PortKind)] =
        if is_mx || starts_any(&label, &["smtp", "mx", "mailrelay", "mailout", "post"]) {
            &[
                (465, PortKind::DirectTls),
                (587, PortKind::StartTls),
                (25, PortKind::StartTls),
            ]
        } else if starts_any(&label, &["imap", "webmail", "mail"]) {
            &[
                (993, PortKind::DirectTls),
                (995, PortKind::DirectTls),
                (465, PortKind::DirectTls),
                (587, PortKind::StartTls),
            ]
        } else if label.starts_with("pop") {
            &[(995, PortKind::DirectTls)]
        } else if starts_any(&label, &["sip", "sips"]) {
            &[(5061, PortKind::DirectTls)]
        } else if starts_any(&label, &["ldap", "ldaps", "directory"]) {
            &[(636, PortKind::DirectTls)]
        } else if starts_any(&label, &["mqtt", "broker"]) {
            &[(8883, PortKind::DirectTls)]
        } else if starts_any(&label, &["xmpp", "jabber", "conference", "chat"]) {
            &[(5222, PortKind::StartTls), (5223, PortKind::DirectTls)]
        } else if generic_override.is_empty() {
            GENERIC_WEB
        } else {
            return generic_override
                .iter()
                .take(PORT_CAP)
                .map(|p| (*p, PortKind::DirectTls))
                .collect();
        };
    table.iter().take(PORT_CAP).copied().collect()
}

fn starts_any(label: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| label.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_matching_is_ordered() {
        let smtp = ports_for_host("mx1c.example.com", &[], false);
        assert_eq!(smtp.len(), 3);
        assert_eq!(smtp[0].0, 465);
        assert!(matches!(smtp[1].1, PortKind::StartTls));

        let mail = ports_for_host("webmail.example.pl", &[], false);
        assert_eq!(mail[0].0, 993);
        assert_eq!(mail.len(), 4);

        let xmpp = ports_for_host("conference.examplex.com", &[], false);
        assert_eq!(
            xmpp.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![5222, 5223]
        );

        let web = ports_for_host("vpn.example.pl", &[], false);
        assert_eq!(
            web.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![8443, 9443, 4443, 8843, 10000]
        );
        assert_eq!(web.len(), PORT_CAP);
    }

    #[test]
    fn generic_override_replaces_web_list() {
        let ports = ports_for_host("vpn.example.pl", &[7000, 7001, 7002], false);
        assert_eq!(
            ports.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![7000, 7001, 7002]
        );
        let smtp = ports_for_host("mx.example.pl", &[7000], false);
        assert_eq!(smtp[0].0, 465);
    }

    #[test]
    fn port_cap_holds_for_every_family() {
        for name in [
            "mx.a.pl",
            "mail.a.pl",
            "pop.a.pl",
            "sip.a.pl",
            "ldap.a.pl",
            "mqtt.a.pl",
            "xmpp.a.pl",
            "web.a.pl",
        ] {
            assert!(ports_for_host(name, &[], false).len() <= PORT_CAP, "{name}");
        }
    }
}
