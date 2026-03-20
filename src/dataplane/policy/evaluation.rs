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
        let (decision, group, _) =
            self.evaluate_with_source_group_detailed_borrowed(meta, tls, verifier);
        (decision, group.map(str::to_owned))
    }

    pub fn evaluate_with_source_group_detailed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>, bool) {
        let (decision, group, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_borrowed(meta, tls, verifier);
        (
            decision,
            group.map(str::to_owned),
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_detailed_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<&str>, bool) {
        let (decision, group_idx, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw_index_borrowed(meta, tls, verifier);
        (
            self.apply_enforcement_mode(decision),
            group_idx.and_then(|idx| self.groups.get(idx).map(|group| group.id.as_str())),
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_effective_and_raw(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, PolicyDecision, Option<String>, bool) {
        let (effective, raw, group, intercept_requires_service) =
            self.evaluate_with_source_group_effective_and_raw_borrowed(meta, tls, verifier);
        (
            effective,
            raw,
            group.map(str::to_owned),
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_effective_and_raw_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, PolicyDecision, Option<&str>, bool) {
        let (raw, group_idx, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw_index_borrowed(meta, tls, verifier);
        (
            self.apply_enforcement_mode(raw),
            raw,
            group_idx.and_then(|idx| self.groups.get(idx).map(|group| group.id.as_str())),
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_effective_and_raw_exact_index_borrowed(
        &self,
        exact_source_group_index: &ExactSourceGroupIndex,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, PolicyDecision, Option<&str>, bool) {
        if exact_source_group_index.matches_generation(self.generation())
            && exact_source_group_index.has_candidates()
        {
            let (effective, raw, group_idx, intercept_requires_service) = self
                .evaluate_with_source_group_effective_and_raw_index_for_group_indices_borrowed(
                    exact_source_group_index.group_indices(meta.src_ip),
                    exact_source_group_index.fallback_group_indices(),
                    meta,
                    tls,
                    verifier,
                );
            (
                effective,
                raw,
                group_idx.and_then(|idx| self.groups.get(idx).map(|group| group.id.as_str())),
                intercept_requires_service,
            )
        } else {
            self.evaluate_with_source_group_effective_and_raw_borrowed(meta, tls, verifier)
        }
    }

    pub fn evaluate_with_source_group_detailed_raw(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>, bool) {
        let (decision, group, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw_borrowed(meta, tls, verifier);
        (
            decision,
            group.map(str::to_owned),
            intercept_requires_service,
        )
    }

    pub fn evaluate_with_source_group_detailed_raw_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<&str>, bool) {
        let (decision, group_idx, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw_index_borrowed(meta, tls, verifier);
        (
            decision,
            group_idx.and_then(|idx| self.groups.get(idx).map(|group| group.id.as_str())),
            intercept_requires_service,
        )
    }

    pub(crate) fn evaluate_with_source_group_effective_and_raw_index_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, PolicyDecision, Option<usize>, bool) {
        let (raw, group_idx, intercept_requires_service) =
            self.evaluate_with_source_group_detailed_raw_index_borrowed(meta, tls, verifier);
        (
            self.apply_enforcement_mode(raw),
            raw,
            group_idx,
            intercept_requires_service,
        )
    }

    pub(crate) fn evaluate_with_source_group_detailed_raw_index_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<usize>, bool) {
        self.evaluate_with_source_group_detailed_for_mode_index_borrowed(
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
        let (decision, group, matched) =
            self.evaluate_audit_rules_with_source_group_borrowed(meta, tls, verifier);
        (decision, group.map(str::to_owned), matched)
    }

    pub fn evaluate_audit_rules_with_source_group_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<&str>, bool) {
        let (decision, group_idx, _) = self
            .evaluate_with_source_group_detailed_for_mode_index_borrowed(
                meta,
                tls,
                verifier,
                RuleMode::Audit,
                false,
            );
        let group = group_idx.and_then(|idx| self.groups.get(idx).map(|group| group.id.as_str()));
        let matched = group.is_some();
        (decision, group, matched)
    }

    pub(crate) fn evaluate_audit_rules_with_source_group_index_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<usize>, bool) {
        let (decision, group_idx, _) = self
            .evaluate_with_source_group_detailed_for_mode_index_borrowed(
                meta,
                tls,
                verifier,
                RuleMode::Audit,
                false,
            );
        let matched = group_idx.is_some();
        (decision, group_idx, matched)
    }

    fn evaluate_with_source_group_detailed_for_mode_index_borrowed(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
        selected_mode: RuleMode,
        include_defaults: bool,
    ) -> (PolicyDecision, Option<usize>, bool) {
        evaluate_with_source_group_detailed_for_mode_full_scan_index(
            self,
            meta,
            tls,
            verifier,
            selected_mode,
            include_defaults,
        )
    }

    fn apply_enforcement_mode(&self, decision: PolicyDecision) -> PolicyDecision {
        if self.enforcement_mode == EnforcementMode::Audit && decision == PolicyDecision::Deny {
            return PolicyDecision::Allow;
        }
        decision
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        if self.contains_internal_exact_source(ip) {
            return true;
        }
        if self
            .internal_static_sources()
            .iter()
            .any(|cidr| cidr.contains(ip))
        {
            return true;
        }
        self.internal_dynamic_sources()
            .iter()
            .any(|dynamic| dynamic.contains(ip))
    }

    pub(crate) fn evaluate_with_source_group_effective_and_raw_index_for_group_indices_borrowed(
        &self,
        group_indices: Option<&[usize]>,
        fallback_group_indices: Option<&[usize]>,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, PolicyDecision, Option<usize>, bool) {
        let (raw, group_idx, intercept_requires_service) =
            evaluate_with_source_group_detailed_for_mode_exact_group_indices_index(
                self,
                group_indices,
                fallback_group_indices,
                meta,
                tls,
                verifier,
                RuleMode::Enforce,
                true,
            );
        (
            self.apply_enforcement_mode(raw),
            raw,
            group_idx,
            intercept_requires_service,
        )
    }

    pub(crate) fn evaluate_audit_rules_with_source_group_index_for_group_indices_borrowed(
        &self,
        group_indices: Option<&[usize]>,
        fallback_group_indices: Option<&[usize]>,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<usize>, bool) {
        let (decision, group_idx, _) =
            evaluate_with_source_group_detailed_for_mode_exact_group_indices_index(
                self,
                group_indices,
                fallback_group_indices,
                meta,
                tls,
                verifier,
                RuleMode::Audit,
                false,
            );
        let matched = group_idx.is_some();
        (decision, group_idx, matched)
    }
}

#[inline(always)]
pub(crate) fn evaluate_with_source_group_detailed_for_mode_full_scan_index(
    snapshot: &PolicySnapshot,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: Option<&TlsVerifier>,
    selected_mode: RuleMode,
    include_defaults: bool,
) -> (PolicyDecision, Option<usize>, bool) {
    if selected_mode == RuleMode::Audit {
        for &group_idx in snapshot.audit_group_indices() {
            let Some(group) = snapshot.groups.get(group_idx) else {
                continue;
            };
            if !group.sources.contains(meta.src_ip) {
                continue;
            }
            if let Some(result) = evaluate_group_for_mode(
                snapshot,
                group_idx,
                group,
                meta,
                tls,
                verifier,
                selected_mode,
            ) {
                return result;
            }
        }
    } else {
        for (group_idx, group) in snapshot.groups.iter().enumerate() {
            if !group.sources.contains(meta.src_ip) {
                continue;
            }
            if let Some(result) = evaluate_group_for_mode(
                snapshot,
                group_idx,
                group,
                meta,
                tls,
                verifier,
                selected_mode,
            ) {
                return result;
            }

            if include_defaults && selected_mode == RuleMode::Enforce {
                if let Some(action) = group.default_action {
                    return (
                        match action {
                            RuleAction::Allow => PolicyDecision::Allow,
                            RuleAction::Deny => PolicyDecision::Deny,
                        },
                        Some(group_idx),
                        false,
                    );
                }
            }
        }
    }

    default_policy_decision(snapshot, selected_mode, include_defaults)
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_with_source_group_detailed_for_mode_exact_group_indices_index(
    snapshot: &PolicySnapshot,
    group_indices: Option<&[usize]>,
    fallback_group_indices: Option<&[usize]>,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: Option<&TlsVerifier>,
    selected_mode: RuleMode,
    include_defaults: bool,
) -> (PolicyDecision, Option<usize>, bool) {
    let exact_groups = group_indices.unwrap_or(&[]);
    let fallback_groups = fallback_group_indices.unwrap_or(&[]);
    let mut exact_pos = 0usize;
    let mut fallback_pos = 0usize;

    while exact_pos < exact_groups.len() || fallback_pos < fallback_groups.len() {
        let choose_exact = match (
            exact_groups.get(exact_pos).copied(),
            fallback_groups.get(fallback_pos).copied(),
        ) {
            (Some(exact_idx), Some(fallback_idx)) => exact_idx <= fallback_idx,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let group_idx = if choose_exact {
            let idx = exact_groups[exact_pos];
            exact_pos += 1;
            idx
        } else {
            let idx = fallback_groups[fallback_pos];
            fallback_pos += 1;
            idx
        };
        let Some(group) = snapshot.groups.get(group_idx) else {
            continue;
        };
        if selected_mode == RuleMode::Audit && !snapshot.group_has_audit_rules(group_idx) {
            continue;
        }
        if !choose_exact && !group.sources.contains(meta.src_ip) {
            continue;
        }
        if let Some(result) = evaluate_group_for_mode(
            snapshot,
            group_idx,
            group,
            meta,
            tls,
            verifier,
            selected_mode,
        ) {
            return result;
        }

        if include_defaults && selected_mode == RuleMode::Enforce {
            if let Some(action) = group.default_action {
                return (
                    match action {
                        RuleAction::Allow => PolicyDecision::Allow,
                        RuleAction::Deny => PolicyDecision::Deny,
                    },
                    Some(group_idx),
                    false,
                );
            }
        }
    }

    default_policy_decision(snapshot, selected_mode, include_defaults)
}

#[inline(always)]
fn evaluate_group_for_mode(
    snapshot: &PolicySnapshot,
    group_idx: usize,
    group: &SourceGroup,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: Option<&TlsVerifier>,
    selected_mode: RuleMode,
) -> Option<(PolicyDecision, Option<usize>, bool)> {
    if let Some(indices) =
        snapshot.candidate_rule_indices_for_group(group_idx, selected_mode, meta.proto, meta.dst_ip)
    {
        for &rule_idx in indices {
            let Some(rule) = group.rules.get(rule_idx) else {
                continue;
            };
            if !rule_matches_prefiltered(&rule.matcher, meta) {
                continue;
            }
            if let Some((decision, _, intercept_requires_service)) =
                evaluate_matched_rule(group, rule, meta, tls, verifier)
            {
                return Some((decision, Some(group_idx), intercept_requires_service));
            }
        }
        return None;
    }

    for rule in &group.rules {
        if rule.mode != selected_mode {
            continue;
        }
        if !rule_matches_basic(&rule.matcher, meta) {
            continue;
        }
        if let Some((decision, _, intercept_requires_service)) =
            evaluate_matched_rule(group, rule, meta, tls, verifier)
        {
            return Some((decision, Some(group_idx), intercept_requires_service));
        }
    }

    None
}

#[inline(always)]
fn default_policy_decision(
    snapshot: &PolicySnapshot,
    selected_mode: RuleMode,
    include_defaults: bool,
) -> (PolicyDecision, Option<usize>, bool) {
    if include_defaults && selected_mode == RuleMode::Enforce {
        return (
            match snapshot.default_policy {
                DefaultPolicy::Allow => PolicyDecision::Allow,
                DefaultPolicy::Deny => PolicyDecision::Deny,
            },
            None,
            false,
        );
    }

    (PolicyDecision::Allow, None, false)
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

fn rule_matches_prefiltered(matcher: &RuleMatch, meta: &PacketMeta) -> bool {
    if let Some(dst_ips) = &matcher.dst_ips {
        if !dst_ips.contains(meta.dst_ip) {
            return false;
        }
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

fn evaluate_matched_rule<'a>(
    group: &'a SourceGroup,
    rule: &Rule,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: Option<&TlsVerifier>,
) -> Option<(PolicyDecision, Option<&'a str>, bool)> {
    if let Some(tls_match) = &rule.matcher.tls {
        if meta.proto != 6 {
            return None;
        }
        if matches!(tls_match.mode, TlsMode::Intercept) {
            return Some((
                match rule.action {
                    RuleAction::Allow => PolicyDecision::Allow,
                    RuleAction::Deny => PolicyDecision::Deny,
                },
                Some(group.id.as_str()),
                true,
            ));
        }
        let Some(obs) = tls else {
            return Some((PolicyDecision::PendingTls, Some(group.id.as_str()), false));
        };
        let Some(verifier) = verifier else {
            return Some((PolicyDecision::Deny, Some(group.id.as_str()), false));
        };
        match tls_match.evaluate(obs, verifier) {
            TlsMatchOutcome::Match => Some((
                match rule.action {
                    RuleAction::Allow => PolicyDecision::Allow,
                    RuleAction::Deny => PolicyDecision::Deny,
                },
                Some(group.id.as_str()),
                false,
            )),
            TlsMatchOutcome::Mismatch => None,
            TlsMatchOutcome::Pending => {
                Some((PolicyDecision::PendingTls, Some(group.id.as_str()), false))
            }
            TlsMatchOutcome::Deny => Some((PolicyDecision::Deny, Some(group.id.as_str()), false)),
        }
    } else {
        Some((
            match rule.action {
                RuleAction::Allow => PolicyDecision::Allow,
                RuleAction::Deny => PolicyDecision::Deny,
            },
            Some(group.id.as_str()),
            false,
        ))
    }
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }

    ranges.iter().any(|range| range.contains(port))
}
