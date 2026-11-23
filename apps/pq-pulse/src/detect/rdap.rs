use serde_json::Value;

use pq_core::evidence::collectors::rdap::{
    RdapCollector as CollectorImpl, RdapRequest, RdapTarget,
};
use pq_core::evidence::freshness::FreshnessRequirement;

use crate::evidence::Evidence;
use crate::model::RdapEvidence;

use crate::providers::match_vendor;

/// Caller-side staleness bound for this path (matches the default policy window).
const POLICY_BOUND_SECS: u64 = 604800;

pub(crate) fn rdap_lookup(evidence: &Evidence, ip: &str) -> Option<RdapEvidence> {
    // One canonical RDAP collection: the provider is resolved through the
    // IANA bootstrap (itself a cached collection), and the registration
    // answer is reused across every hostname that resolves to this IP.
    let request = RdapRequest {
        target: RdapTarget::Ip(ip.to_string()),
        provider: None,
    };
    let outcome = evidence
        .scan
        .collect(
            &CollectorImpl {
                http: evidence.http_executor.clone(),
            },
            request,
            FreshnessRequirement::MaxAge(std::time::Duration::from_secs(POLICY_BOUND_SECS)),
        )
        .ok()?;
    let data: Value = outcome.data?;
    rdap_evidence_from_json(&data)
}

/// Extraction from the RDAP JSON: netname + registrant org.
fn rdap_evidence_from_json(json: &Value) -> Option<RdapEvidence> {
    let netname = json["name"].as_str().unwrap_or("").to_string();

    let mut org_name = String::new();
    let mut best_rank = -1;
    if let Some(entities) = json["entities"].as_array() {
        for entity in entities {
            let rank = entity["roles"]
                .as_array()
                .map(|roles| {
                    if roles.iter().any(|r| r.as_str() == Some("registrant")) {
                        2
                    } else if roles.iter().any(|r| r.as_str() == Some("abuse")) {
                        0
                    } else {
                        1
                    }
                })
                .unwrap_or(1);
            if let Some(vcard) = entity["vcardArray"].as_array()
                && vcard.len() > 1
                && let Some(items) = vcard[1].as_array()
            {
                for item in items {
                    if let Some(arr) = item.as_array()
                        && arr.first().and_then(|f| f.as_str()) == Some("fn")
                        && arr.len() > 3
                        && let Some(name) = arr.get(3).and_then(|v| v.as_str())
                        && rank > best_rank
                    {
                        best_rank = rank;
                        org_name = name.to_string();
                    }
                }
            }
        }
    }

    let combined = format!("{netname} {org_name}");
    let vendor = match_vendor(&combined);
    Some(RdapEvidence {
        netname,
        vendor,
        org: (!org_name.is_empty()).then_some(org_name),
    })
}
