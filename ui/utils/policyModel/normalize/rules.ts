import type {
  PolicyRule,
  PolicyRuleMatch,
  PolicySourceGroup,
} from '../../../types';
import { createSourceGroupClientKey } from '../factories';
import {
  asNumberList,
  asPolicyAction,
  asRuleMode,
  asString,
  asStringList,
  isObject,
  sanitizeOptionalNumber,
} from './shared';
import { normalizeSources } from './sources';
import { normalizeTlsMatch } from './tls';

function normalizeRuleMatch(value: unknown): PolicyRuleMatch {
  if (!isObject(value)) {
    return {
      dst_cidrs: [],
      dst_ips: [],
      src_ports: [],
      dst_ports: [],
      icmp_types: [],
      icmp_codes: [],
    };
  }

  const dnsHostname = asString(value.dns_hostname);
  const proto = typeof value.proto === 'number' ? String(value.proto) : asString(value.proto);
  const tls = normalizeTlsMatch(value.tls);

  return {
    dst_cidrs: asStringList(value.dst_cidrs),
    dst_ips: asStringList(value.dst_ips),
    ...(dnsHostname ? { dns_hostname: dnsHostname } : {}),
    ...(proto ? { proto } : {}),
    src_ports: asStringList(value.src_ports),
    dst_ports: asStringList(value.dst_ports),
    icmp_types: asNumberList(value.icmp_types),
    icmp_codes: asNumberList(value.icmp_codes),
    ...(tls ? { tls } : {}),
  };
}

function normalizeRule(value: unknown, index: number): PolicyRule {
  if (!isObject(value)) {
    return {
      id: `rule-${index + 1}`,
      action: 'deny',
      mode: 'enforce',
      match: normalizeRuleMatch(undefined),
    };
  }
  const priority = sanitizeOptionalNumber(value.priority);
  return {
    id: asString(value.id) ?? `rule-${index + 1}`,
    ...(typeof priority === 'number' ? { priority } : {}),
    action: asPolicyAction(value.action, 'deny'),
    mode: asRuleMode(value.mode),
    match: normalizeRuleMatch(value.match),
  };
}

export function normalizeSourceGroup(value: unknown, index: number): PolicySourceGroup {
  if (!isObject(value)) {
    return {
      id: `group-${index + 1}`,
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [],
    };
  }
  const rules = Array.isArray(value.rules)
    ? value.rules.map((entry, i) => normalizeRule(entry, i))
    : [];
  const priority = sanitizeOptionalNumber(value.priority);
  const defaultAction = asString(value.default_action);

  return {
    client_key: asString(value.client_key) ?? createSourceGroupClientKey(asString(value.id) ?? `group-${index + 1}`),
    id: asString(value.id) ?? `group-${index + 1}`,
    ...(typeof priority === 'number' ? { priority } : {}),
    sources: normalizeSources(value.sources),
    rules,
    ...(defaultAction ? { default_action: asPolicyAction(defaultAction) } : {}),
  };
}
