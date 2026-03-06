import type { PolicyRule, PolicyRuleMatch } from '../../../types';
import { sanitizeNumberList, sanitizeStringList } from './shared';
import { sanitizeTls } from './tls';

function sanitizeRuleMatch(value: PolicyRuleMatch | undefined): PolicyRuleMatch {
  const match: PolicyRuleMatch = {
    dst_cidrs: sanitizeStringList(value?.dst_cidrs),
    dst_ips: sanitizeStringList(value?.dst_ips),
    src_ports: sanitizeStringList(value?.src_ports),
    dst_ports: sanitizeStringList(value?.dst_ports),
    icmp_types: sanitizeNumberList(value?.icmp_types),
    icmp_codes: sanitizeNumberList(value?.icmp_codes),
  };
  const dns_hostname = value?.dns_hostname?.trim();
  if (dns_hostname) match.dns_hostname = dns_hostname;
  const proto = value?.proto?.trim();
  if (proto) match.proto = proto;
  const tls = sanitizeTls(value?.tls);
  if (tls) match.tls = tls;
  return match;
}

export function sanitizeRule(value: PolicyRule): PolicyRule {
  const normalizedRule: PolicyRule = {
    id: value.id.trim(),
    action: value.action,
    match: sanitizeRuleMatch(value.match),
  };
  if (typeof value.priority === 'number') normalizedRule.priority = value.priority;
  if (value.mode) normalizedRule.mode = value.mode;
  return normalizedRule;
}
