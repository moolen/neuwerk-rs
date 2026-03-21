use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::dataplane::policy::CidrV4;

use super::feeds::{ThreatIndicatorSnapshotItem, ThreatSnapshot};
use super::types::{ThreatIndicatorType, ThreatSeverity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatMatch {
    pub indicator: String,
    pub indicator_type: ThreatIndicatorType,
    pub severity: ThreatSeverity,
    pub confidence: Option<u8>,
    pub feed_hits: Vec<ThreatIndicatorSnapshotItem>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatMatcher {
    hostname_hits: HashMap<String, Vec<ThreatIndicatorSnapshotItem>>,
    exact_ip_hits: HashMap<Ipv4Addr, Vec<ThreatIndicatorSnapshotItem>>,
    cidr_ip_hits: Vec<(CidrV4, ThreatIndicatorSnapshotItem)>,
}

impl ThreatMatcher {
    pub fn from_snapshot(snapshot: &ThreatSnapshot) -> Self {
        let mut matcher = Self::default();
        for item in snapshot.items.iter().cloned() {
            match item.indicator_type {
                ThreatIndicatorType::Hostname => {
                    let key = normalize_hostname(&item.indicator);
                    matcher.hostname_hits.entry(key).or_default().push(item);
                }
                ThreatIndicatorType::Ip => {
                    if let Some(cidr) = parse_cidr_v4(&item.indicator) {
                        matcher.cidr_ip_hits.push((cidr, item));
                    } else if let Ok(ip) = item.indicator.parse::<Ipv4Addr>() {
                        matcher.exact_ip_hits.entry(ip).or_default().push(item);
                    }
                }
            }
        }

        for hits in matcher.hostname_hits.values_mut() {
            sort_hits(hits);
        }
        for hits in matcher.exact_ip_hits.values_mut() {
            sort_hits(hits);
        }
        matcher.cidr_ip_hits.sort_unstable_by(|left, right| {
            left.1
                .feed
                .cmp(&right.1.feed)
                .then_with(|| right.0.prefix().cmp(&left.0.prefix()))
                .then_with(|| left.1.indicator.cmp(&right.1.indicator))
        });
        matcher
    }

    pub fn match_hostname(&self, hostname: &str) -> Option<ThreatMatch> {
        let normalized = normalize_hostname(hostname);
        let hits = self.hostname_hits.get(&normalized)?;
        Some(build_match(
            normalized,
            ThreatIndicatorType::Hostname,
            hits.clone(),
        ))
    }

    pub fn match_ip(&self, ip: Ipv4Addr) -> Option<ThreatMatch> {
        let mut hits = self.exact_ip_hits.get(&ip).cloned().unwrap_or_default();
        for (cidr, hit) in &self.cidr_ip_hits {
            if cidr.contains(ip) {
                hits.push(hit.clone());
            }
        }
        if hits.is_empty() {
            return None;
        }
        Some(build_match(ip.to_string(), ThreatIndicatorType::Ip, hits))
    }
}

fn build_match(
    indicator: String,
    indicator_type: ThreatIndicatorType,
    mut feed_hits: Vec<ThreatIndicatorSnapshotItem>,
) -> ThreatMatch {
    sort_hits(&mut feed_hits);
    let severity = feed_hits
        .iter()
        .map(|item| item.severity)
        .max_by_key(|severity| severity_rank(*severity))
        .unwrap_or(ThreatSeverity::Low);
    let confidence = feed_hits.iter().filter_map(|item| item.confidence).max();
    ThreatMatch {
        indicator,
        indicator_type,
        severity,
        confidence,
        feed_hits,
    }
}

fn sort_hits(hits: &mut Vec<ThreatIndicatorSnapshotItem>) {
    hits.sort_unstable_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| left.feed.cmp(&right.feed))
            .then_with(|| left.indicator.cmp(&right.indicator))
    });
    hits.dedup();
}

fn severity_rank(severity: ThreatSeverity) -> u8 {
    match severity {
        ThreatSeverity::Low => 0,
        ThreatSeverity::Medium => 1,
        ThreatSeverity::High => 2,
        ThreatSeverity::Critical => 3,
    }
}

fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_cidr_v4(indicator: &str) -> Option<CidrV4> {
    let (ip, prefix) = indicator.split_once('/')?;
    let ip = ip.trim().parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.trim().parse::<u8>().ok()?;
    (prefix <= 32).then_some(CidrV4::new(ip, prefix))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::ThreatMatcher;
    use crate::controlplane::threat_intel::feeds::{snapshot_with_cidr, snapshot_with_hostname};
    use crate::controlplane::threat_intel::types::ThreatSeverity;

    #[test]
    fn matcher_exact_hostname_is_case_insensitive() {
        let snapshot = snapshot_with_hostname("Bad.Example.com", ThreatSeverity::High, "threatfox");
        let matcher = ThreatMatcher::from_snapshot(&snapshot);
        let hit = matcher.match_hostname("bad.example.com").expect("match");
        assert_eq!(hit.feed_hits[0].feed, "threatfox");
    }

    #[test]
    fn matcher_trims_trailing_dot_before_hostname_match() {
        let snapshot =
            snapshot_with_hostname("Bad.Example.com.", ThreatSeverity::High, "threatfox");
        let matcher = ThreatMatcher::from_snapshot(&snapshot);
        let hit = matcher.match_hostname("bad.example.com").expect("match");
        assert_eq!(hit.indicator, "bad.example.com");
    }

    #[test]
    fn matcher_supports_cidr_ip_hits() {
        let snapshot =
            snapshot_with_cidr("203.0.113.0/24", ThreatSeverity::Critical, "spamhaus_drop");
        let matcher = ThreatMatcher::from_snapshot(&snapshot);
        assert!(matcher.match_ip(Ipv4Addr::new(203, 0, 113, 42)).is_some());
    }

    #[test]
    fn matcher_supports_exact_ipv4_hits() {
        let snapshot = snapshot_with_cidr("203.0.113.42", ThreatSeverity::Critical, "threatfox");
        let matcher = ThreatMatcher::from_snapshot(&snapshot);
        let hit = matcher
            .match_ip(Ipv4Addr::new(203, 0, 113, 42))
            .expect("match");
        assert_eq!(hit.indicator, "203.0.113.42");
        assert_eq!(hit.feed_hits[0].feed, "threatfox");
    }
}
