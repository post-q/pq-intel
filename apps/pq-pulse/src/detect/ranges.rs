use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

use pq_core::evidence::collectors::http_collector::HttpRequest_;
use pq_core::evidence::freshness::FreshnessRequirement;

use crate::evidence::Evidence;
use crate::model::Vendor;

/// Caller-side staleness bound for this path (matches the default policy window).
const POLICY_BOUND_SECS: u64 = 86400;

pub(crate) type VendorRanges = Vec<(Vendor, Vec<String>)>;

/// Vendor IP ranges, store-backed: each list is an HTTP collection under the
/// `http` policy (roughly a day), so runs inside the freshness window cost
/// zero network requests and the old /tmp cache file is gone.
fn fetch_vendor_ranges(evidence: &Evidence) -> VendorRanges {
    let mut ranges: VendorRanges = Vec::new();

    let cloudflare = fetch_text(evidence, "https://www.cloudflare.com/ips-v4")
        .map(|body| {
            body.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|list| !list.is_empty());
    if let Some(cf) = cloudflare {
        ranges.push((Vendor::Cloudflare, cf));
    }

    let fastly = fetch_text(evidence, "https://api.fastly.com/public-ip-list")
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .map(|json| {
            json["addresses"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        })
        .filter(|list: &Vec<String>| !list.is_empty());
    if let Some(fastly) = fastly {
        ranges.push((Vendor::Fastly, fastly));
    }

    let cloudfront = fetch_text(evidence, "https://ip-ranges.amazonaws.com/ip-ranges.json")
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .map(|json| {
            json["prefixes"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|v| v["service"].as_str() == Some("CLOUDFRONT"))
                        .filter_map(|v| v["ip_prefix"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        })
        .filter(|list: &Vec<String>| !list.is_empty());
    if let Some(cloudfront) = cloudfront {
        ranges.push((Vendor::CloudFront, cloudfront));
    }

    ranges
}

/// One HTTP GET through the store; the body as text when collected or
/// cached successfully.
fn fetch_text(evidence: &Evidence, url: &str) -> Option<String> {
    let request = HttpRequest_::get(url).ok()?;
    let outcome = evidence
        .scan
        .collect(
            &evidence.http,
            request,
            FreshnessRequirement::MaxAge(std::time::Duration::from_secs(POLICY_BOUND_SECS)),
        )
        .ok()?;
    let observation = outcome.data?;
    Some(String::from_utf8_lossy(&observation.body).into_owned())
}

pub(crate) fn get_vendor_ranges(evidence: &Evidence) -> VendorRanges {
    fetch_vendor_ranges(evidence)
}

/// Returns the owning vendor and the matched CIDR.
pub(crate) fn ip_in_ranges(ip: &IpAddr, ranges: &VendorRanges) -> Option<(Vendor, String)> {
    for (vendor, cidrs) in ranges {
        for cidr in cidrs {
            if let Ok(net) = cidr.parse::<IpNet>()
                && net.contains(ip)
            {
                return Some((*vendor, cidr.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_in_ranges_returns_vendor_and_cidr() {
        let ranges = vec![(Vendor::Cloudflare, vec!["104.16.0.0/12".to_string()])];
        let inside: IpAddr = "104.16.132.229".parse().unwrap();
        assert_eq!(
            ip_in_ranges(&inside, &ranges),
            Some((Vendor::Cloudflare, "104.16.0.0/12".to_string()))
        );
        let outside: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(ip_in_ranges(&outside, &ranges), None);
    }
}
