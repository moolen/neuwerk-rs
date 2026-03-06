use std::net::Ipv4Addr;

use crate::dataplane::tls::{TlsObservation, TlsVerifier};

use super::tls_eval::TlsMatchOutcome;
use super::*;

impl PolicySnapshot {
    pub fn evaluate(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> PolicyDecision {
        self.evaluate_with_source_group(meta, tls, verifier).0
    }

    pub fn evaluate_with_source_group(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>) {
        let (decision, group, _) = self.evaluate_with_source_group_detailed(meta, tls, verifier);
        (decision, group)
    }

    pub fn evaluate_with_source_group_detailed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>, bool) {
        let (decision, group, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw(meta, tls, verifier);
        (
            self.apply_enforcement_mode(decision),
            group,
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_detailed_raw(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>, bool) {
        self.evaluate_with_source_group_detailed_for_mode(
            meta,
            tls,
            verifier,
            RuleMode::Enforce,
            true,
        )
    }

    pub fn evaluate_audit_rules_with_source_group(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>, bool) {
        let (decision, group, _) = self.evaluate_with_source_group_detailed_for_mode(
            meta,
            tls,
            verifier,
            RuleMode::Audit,
            false,
        );
        let matched = group.is_some();
        (decision, group, matched)
    }

    fn evaluate_with_source_group_detailed_for_mode(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
        selected_mode: RuleMode,
        include_defaults: bool,
    ) -> (PolicyDecision, Option<String>, bool) {
        for group in &self.groups {
            if !group.sources.contains(meta.src_ip) {
                continue;
            }

            for rule in &group.rules {
                if rule.mode != selected_mode {
                    continue;
                }
                if !rule_matches_basic(&rule.matcher, meta) {
                    continue;
                }
                if let Some(tls_match) = &rule.matcher.tls {
                    if meta.proto != 6 {
                        continue;
                    }
                    if matches!(tls_match.mode, TlsMode::Intercept) {
                        return (
                            match rule.action {
                                RuleAction::Allow => PolicyDecision::Allow,
                                RuleAction::Deny => PolicyDecision::Deny,
                            },
                            Some(group.id.clone()),
                            true,
                        );
                    }
                    let Some(obs) = tls else {
                        return (PolicyDecision::PendingTls, Some(group.id.clone()), false);
                    };
                    let Some(verifier) = verifier else {
                        return (PolicyDecision::Deny, Some(group.id.clone()), false);
                    };
                    match tls_match.evaluate(obs, verifier) {
                        TlsMatchOutcome::Match => {
                            return (
                                match rule.action {
                                    RuleAction::Allow => PolicyDecision::Allow,
                                    RuleAction::Deny => PolicyDecision::Deny,
                                },
                                Some(group.id.clone()),
                                false,
                            );
                        }
                        TlsMatchOutcome::Mismatch => continue,
                        TlsMatchOutcome::Pending => {
                            return (PolicyDecision::PendingTls, Some(group.id.clone()), false)
                        }
                        TlsMatchOutcome::Deny => {
                            return (PolicyDecision::Deny, Some(group.id.clone()), false)
                        }
                    }
                } else {
                    return (
                        match rule.action {
                            RuleAction::Allow => PolicyDecision::Allow,
                            RuleAction::Deny => PolicyDecision::Deny,
                        },
                        Some(group.id.clone()),
                        false,
                    );
                }
            }

            if include_defaults && selected_mode == RuleMode::Enforce {
                if let Some(action) = group.default_action {
                    return (
                        match action {
                            RuleAction::Allow => PolicyDecision::Allow,
                            RuleAction::Deny => PolicyDecision::Deny,
                        },
                        Some(group.id.clone()),
                        false,
                    );
                }
            }
        }

        if include_defaults && selected_mode == RuleMode::Enforce {
            return (
                match self.default_policy {
                    DefaultPolicy::Allow => PolicyDecision::Allow,
                    DefaultPolicy::Deny => PolicyDecision::Deny,
                },
                None,
                false,
            );
        }

        (PolicyDecision::Allow, None, false)
    }

    fn apply_enforcement_mode(&self, decision: PolicyDecision) -> PolicyDecision {
        if self.enforcement_mode == EnforcementMode::Audit && decision == PolicyDecision::Deny {
            return PolicyDecision::Allow;
        }
        decision
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        self.groups.iter().any(|group| group.sources.contains(ip))
    }
}

fn rule_matches_basic(matcher: &RuleMatch, meta: &PacketMeta) -> bool {
    if let Some(dst_ips) = &matcher.dst_ips {
        if !dst_ips.contains(meta.dst_ip) {
            return false;
        }
    }

    if !matcher.proto.matches(meta.proto) {
        return false;
    }

    if !port_matches(&matcher.src_ports, meta.src_port) {
        return false;
    }

    if !port_matches(&matcher.dst_ports, meta.dst_port) {
        return false;
    }

    if !matcher.icmp_types.is_empty() || !matcher.icmp_codes.is_empty() {
        let Some(icmp_type) = meta.icmp_type else {
            return false;
        };
        if !matcher.icmp_types.is_empty() && !matcher.icmp_types.contains(&icmp_type) {
            return false;
        }
        if let Some(icmp_code) = meta.icmp_code {
            if !matcher.icmp_codes.is_empty() && !matcher.icmp_codes.contains(&icmp_code) {
                return false;
            }
        } else if !matcher.icmp_codes.is_empty() {
            return false;
        }
    }

    true
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }

    ranges.iter().any(|range| range.contains(port))
}
