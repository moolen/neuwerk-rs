import type {
  PolicyAction,
  PolicyConfig,
  PolicyCreateRequest,
  PolicyKubernetesNodeSelector,
  PolicyKubernetesPodSelector,
  PolicyKubernetesSource,
  PolicyMode,
  PolicyRule,
  PolicyRuleMatch,
  PolicySourceGroup,
  PolicySources,
  PolicyTls13Uninspectable,
  PolicyTlsHttpHeadersMatch,
  PolicyTlsHttpPathMatch,
  PolicyTlsHttpPolicy,
  PolicyTlsHttpQueryMatch,
  PolicyTlsHttpRequest,
  PolicyTlsHttpResponse,
  PolicyTlsMatch,
  PolicyTlsMode,
  PolicyTlsNameMatch,
} from '../types';

const POLICY_ACTIONS: PolicyAction[] = ['allow', 'deny'];
const POLICY_MODES: PolicyMode[] = ['disabled', 'audit', 'enforce'];
const RULE_MODES = ['audit', 'enforce'] as const;
const TLS_MODES: PolicyTlsMode[] = ['metadata', 'intercept'];
const TLS13_MODES: PolicyTls13Uninspectable[] = ['allow', 'deny'];

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.floor(value);
  if (typeof value === 'string' && value.trim().length) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.floor(parsed);
  }
  return undefined;
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === 'number' ? String(item) : item))
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

function asNumberList(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => asNumber(item))
    .filter((item): item is number => typeof item === 'number');
}

function asStringMap(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    const key = k.trim();
    const val = asString(v);
    if (!key || !val) continue;
    out[key] = val;
  }
  return out;
}

function asStringListMap(value: unknown): Record<string, string[]> {
  if (!isObject(value)) return {};
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(value)) {
    const key = k.trim();
    if (!key) continue;
    const vals = asStringList(v);
    if (!vals.length) continue;
    out[key] = vals;
  }
  return out;
}

function asPolicyAction(value: unknown, fallback: PolicyAction = 'deny'): PolicyAction {
  const parsed = asString(value)?.toLowerCase();
  return POLICY_ACTIONS.includes(parsed as PolicyAction) ? (parsed as PolicyAction) : fallback;
}

function asPolicyMode(value: unknown, fallback: PolicyMode = 'enforce'): PolicyMode {
  const parsed = asString(value)?.toLowerCase();
  return POLICY_MODES.includes(parsed as PolicyMode) ? (parsed as PolicyMode) : fallback;
}

function asRuleMode(value: unknown): 'audit' | 'enforce' {
  const parsed = asString(value)?.toLowerCase();
  return RULE_MODES.includes(parsed as (typeof RULE_MODES)[number]) ? (parsed as 'audit' | 'enforce') : 'enforce';
}

function asTlsMode(value: unknown): PolicyTlsMode {
  const parsed = asString(value)?.toLowerCase();
  return TLS_MODES.includes(parsed as PolicyTlsMode) ? (parsed as PolicyTlsMode) : 'metadata';
}

function asTls13Mode(value: unknown): PolicyTls13Uninspectable {
  const parsed = asString(value)?.toLowerCase();
  return TLS13_MODES.includes(parsed as PolicyTls13Uninspectable)
    ? (parsed as PolicyTls13Uninspectable)
    : 'deny';
}

function sanitizeOptionalNumber(value: unknown): number | undefined {
  const n = asNumber(value);
  if (typeof n !== 'number' || n < 0) return undefined;
  return n;
}

function isTlsNameMatchEmpty(value?: PolicyTlsNameMatch): boolean {
  if (!value) return true;
  const exact = (value.exact ?? []).filter(Boolean);
  const regex = value.regex?.trim();
  return !exact.length && !regex;
}

function normalizeTlsNameMatch(value: unknown): PolicyTlsNameMatch | undefined {
  if (typeof value === 'string') {
    const regex = value.trim();
    return regex ? { exact: [], regex } : undefined;
  }
  if (Array.isArray(value)) {
    const exact = asStringList(value);
    return exact.length ? { exact } : undefined;
  }
  if (!isObject(value)) return undefined;
  const exact = asStringList(value.exact);
  const regex = asString(value.regex);
  if (!exact.length && !regex) return undefined;
  return {
    exact,
    ...(regex ? { regex } : {}),
  };
}

function normalizeHttpPath(value: unknown): PolicyTlsHttpPathMatch | undefined {
  if (!isObject(value)) return undefined;
  const exact = asStringList(value.exact);
  const prefix = asStringList(value.prefix);
  const regex = asString(value.regex);
  if (!exact.length && !prefix.length && !regex) return undefined;
  return {
    exact,
    prefix,
    ...(regex ? { regex } : {}),
  };
}

function normalizeHttpQuery(value: unknown): PolicyTlsHttpQueryMatch | undefined {
  if (!isObject(value)) return undefined;
  const keys_present = asStringList(value.keys_present);
  const key_values_exact = asStringListMap(value.key_values_exact);
  const key_values_regex = asStringMap(value.key_values_regex);
  if (!keys_present.length && !Object.keys(key_values_exact).length && !Object.keys(key_values_regex).length) {
    return undefined;
  }
  return {
    keys_present,
    key_values_exact,
    key_values_regex,
  };
}

function normalizeHttpHeaders(value: unknown): PolicyTlsHttpHeadersMatch | undefined {
  if (!isObject(value)) return undefined;
  const require_present = asStringList(value.require_present);
  const deny_present = asStringList(value.deny_present);
  const exact = asStringListMap(value.exact);
  const regex = asStringMap(value.regex);
  if (!require_present.length && !deny_present.length && !Object.keys(exact).length && !Object.keys(regex).length) {
    return undefined;
  }
  return {
    require_present,
    deny_present,
    exact,
    regex,
  };
}

function normalizeHttpRequest(value: unknown): PolicyTlsHttpRequest | undefined {
  if (!isObject(value)) return undefined;
  const host = normalizeTlsNameMatch(value.host);
  const methods = asStringList(value.methods).map((method) => method.toUpperCase());
  const path = normalizeHttpPath(value.path);
  const query = normalizeHttpQuery(value.query);
  const headers = normalizeHttpHeaders(value.headers);

  if (!host && !methods.length && !path && !query && !headers) return undefined;
  return {
    ...(host ? { host } : {}),
    methods,
    ...(path ? { path } : {}),
    ...(query ? { query } : {}),
    ...(headers ? { headers } : {}),
  };
}

function normalizeHttpResponse(value: unknown): PolicyTlsHttpResponse | undefined {
  if (!isObject(value)) return undefined;
  const headers = normalizeHttpHeaders(value.headers);
  if (!headers) return undefined;
  return { headers };
}

function normalizeTlsHttp(value: unknown): PolicyTlsHttpPolicy | undefined {
  if (!isObject(value)) return undefined;
  const request = normalizeHttpRequest(value.request);
  const response = normalizeHttpResponse(value.response);
  if (!request && !response) return undefined;
  return {
    ...(request ? { request } : {}),
    ...(response ? { response } : {}),
  };
}

function normalizeTlsMatch(value: unknown): PolicyTlsMatch | undefined {
  if (!isObject(value)) return undefined;
  const mode = asTlsMode(value.mode);
  const sni = normalizeTlsNameMatch(value.sni);
  const server_cn = normalizeTlsNameMatch(value.server_cn);
  const server_san = normalizeTlsNameMatch(value.server_san);
  const server_dn = asString(value.server_dn);
  const fingerprint_sha256 = asStringList(value.fingerprint_sha256);
  const trust_anchors_pem = asStringList(value.trust_anchors_pem);
  const tls13_uninspectable = asTls13Mode(value.tls13_uninspectable);
  const http = normalizeTlsHttp(value.http);

  const hasAnyField =
    mode !== 'metadata' ||
    !!sni ||
    !!server_cn ||
    !!server_san ||
    !!server_dn ||
    fingerprint_sha256.length > 0 ||
    trust_anchors_pem.length > 0 ||
    tls13_uninspectable !== 'deny' ||
    !!http;
  if (!hasAnyField) return undefined;

  return {
    mode,
    ...(sni ? { sni } : {}),
    ...(server_dn ? { server_dn } : {}),
    ...(server_san ? { server_san } : {}),
    ...(server_cn ? { server_cn } : {}),
    fingerprint_sha256,
    trust_anchors_pem,
    tls13_uninspectable,
    ...(http ? { http } : {}),
  };
}

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
  return {
    dst_cidrs: asStringList(value.dst_cidrs),
    dst_ips: asStringList(value.dst_ips),
    ...(asString(value.dns_hostname) ? { dns_hostname: asString(value.dns_hostname) } : {}),
    ...(asString(value.proto) || typeof value.proto === 'number'
      ? { proto: typeof value.proto === 'number' ? String(value.proto) : asString(value.proto) }
      : {}),
    src_ports: asStringList(value.src_ports),
    dst_ports: asStringList(value.dst_ports),
    icmp_types: asNumberList(value.icmp_types),
    icmp_codes: asNumberList(value.icmp_codes),
    ...(normalizeTlsMatch(value.tls) ? { tls: normalizeTlsMatch(value.tls) } : {}),
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
  return {
    id: asString(value.id) ?? `rule-${index + 1}`,
    ...(typeof sanitizeOptionalNumber(value.priority) === 'number'
      ? { priority: sanitizeOptionalNumber(value.priority) }
      : {}),
    action: asPolicyAction(value.action, 'deny'),
    mode: asRuleMode(value.mode),
    match: normalizeRuleMatch(value.match),
  };
}

function normalizeKubernetesPodSelector(value: unknown): PolicyKubernetesPodSelector | undefined {
  if (!isObject(value)) return undefined;
  const namespace = asString(value.namespace) ?? '';
  const match_labels = asStringMap(value.match_labels);
  if (!namespace && !Object.keys(match_labels).length) return undefined;
  return {
    namespace,
    match_labels,
  };
}

function normalizeKubernetesNodeSelector(value: unknown): PolicyKubernetesNodeSelector | undefined {
  if (!isObject(value)) return undefined;
  return {
    match_labels: asStringMap(value.match_labels),
  };
}

function normalizeKubernetesSource(value: unknown): PolicyKubernetesSource | undefined {
  if (!isObject(value)) return undefined;
  const integration = asString(value.integration) ?? '';
  const pod_selector = normalizeKubernetesPodSelector(value.pod_selector);
  const node_selector = normalizeKubernetesNodeSelector(value.node_selector);
  if (!integration && !pod_selector && !node_selector) return undefined;
  return {
    integration,
    ...(pod_selector ? { pod_selector } : {}),
    ...(node_selector ? { node_selector } : {}),
  };
}

function normalizeSources(value: unknown): PolicySources {
  if (!isObject(value)) return { cidrs: [], ips: [], kubernetes: [] };
  const kubernetes = Array.isArray(value.kubernetes)
    ? value.kubernetes
        .map((entry) => normalizeKubernetesSource(entry))
        .filter((entry): entry is PolicyKubernetesSource => !!entry)
    : [];
  return {
    cidrs: asStringList(value.cidrs),
    ips: asStringList(value.ips),
    kubernetes,
  };
}

function normalizeSourceGroup(value: unknown, index: number): PolicySourceGroup {
  if (!isObject(value)) {
    return {
      id: `group-${index + 1}`,
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [],
    };
  }
  const rules = Array.isArray(value.rules) ? value.rules.map((entry, i) => normalizeRule(entry, i)) : [];
  return {
    id: asString(value.id) ?? `group-${index + 1}`,
    ...(typeof sanitizeOptionalNumber(value.priority) === 'number'
      ? { priority: sanitizeOptionalNumber(value.priority) }
      : {}),
    sources: normalizeSources(value.sources),
    rules,
    ...(asString(value.default_action) ? { default_action: asPolicyAction(value.default_action) } : {}),
  };
}

export function createEmptyRule(id = 'rule-1'): PolicyRule {
  return {
    id,
    action: 'allow',
    mode: 'enforce',
    match: {
      dst_cidrs: [],
      dst_ips: [],
      src_ports: [],
      dst_ports: [],
      icmp_types: [],
      icmp_codes: [],
    },
  };
}

export function createRuleTemplate(template: 'dns_allow' | 'l4_allow' | 'tls_metadata' | 'tls_intercept', id: string): PolicyRule {
  switch (template) {
    case 'dns_allow':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          dns_hostname: '^api\\.example\\.com$',
          src_ports: [],
          dst_ports: [],
          icmp_types: [],
          icmp_codes: [],
        },
      };
    case 'l4_allow':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: ['0.0.0.0/0'],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
        },
      };
    case 'tls_metadata':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
          tls: {
            mode: 'metadata',
            sni: { exact: ['api.example.com'] },
            server_san: { exact: ['api.example.com'] },
            fingerprint_sha256: [],
            trust_anchors_pem: [],
            tls13_uninspectable: 'deny',
          },
        },
      };
    case 'tls_intercept':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
          tls: {
            mode: 'intercept',
            tls13_uninspectable: 'deny',
            fingerprint_sha256: [],
            trust_anchors_pem: [],
            http: {
              request: {
                host: { exact: ['api.example.com'] },
                methods: ['GET'],
                path: { exact: [], prefix: ['/v1/'] },
              },
            },
          },
        },
      };
    default:
      return createEmptyRule(id);
  }
}

export function createEmptySourceGroup(id = 'group-1'): PolicySourceGroup {
  return {
    id,
    priority: 0,
    sources: {
      cidrs: [],
      ips: [],
      kubernetes: [],
    },
    rules: [],
    default_action: 'deny',
  };
}

export function createEmptyPolicyRequest(): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_policy: 'deny',
      source_groups: [],
    },
  };
}

export function normalizePolicyConfig(value: unknown): PolicyConfig {
  if (!isObject(value)) {
    return {
      default_policy: 'deny',
      source_groups: [],
    };
  }
  const source_groups = Array.isArray(value.source_groups)
    ? value.source_groups.map((entry, idx) => normalizeSourceGroup(entry, idx))
    : [];
  return {
    ...(asString(value.default_policy) ? { default_policy: asPolicyAction(value.default_policy) } : {}),
    source_groups,
  };
}

export function normalizePolicyRequest(value: unknown): PolicyCreateRequest {
  if (!isObject(value)) {
    return createEmptyPolicyRequest();
  }
  return {
    mode: asPolicyMode(value.mode),
    policy: normalizePolicyConfig(value.policy),
  };
}

export function clonePolicyRequest(value: PolicyCreateRequest): PolicyCreateRequest {
  return JSON.parse(JSON.stringify(value)) as PolicyCreateRequest;
}

function sanitizeTlsNameMatch(value?: PolicyTlsNameMatch): PolicyTlsNameMatch | undefined {
  if (!value) return undefined;
  const exact = (value.exact ?? []).map((item) => item.trim()).filter(Boolean);
  const regex = value.regex?.trim();
  if (!exact.length && !regex) return undefined;
  return {
    exact,
    ...(regex ? { regex } : {}),
  };
}

function sanitizeHeaders(value?: PolicyTlsHttpHeadersMatch): PolicyTlsHttpHeadersMatch | undefined {
  if (!value) return undefined;
  const require_present = (value.require_present ?? []).map((v) => v.trim()).filter(Boolean);
  const deny_present = (value.deny_present ?? []).map((v) => v.trim()).filter(Boolean);
  const exact: Record<string, string[]> = {};
  for (const [k, vals] of Object.entries(value.exact ?? {})) {
    const key = k.trim();
    const cleaned = (vals ?? []).map((v) => v.trim()).filter(Boolean);
    if (key && cleaned.length) exact[key] = cleaned;
  }
  const regex: Record<string, string> = {};
  for (const [k, v] of Object.entries(value.regex ?? {})) {
    const key = k.trim();
    const pattern = v.trim();
    if (key && pattern) regex[key] = pattern;
  }
  if (!require_present.length && !deny_present.length && !Object.keys(exact).length && !Object.keys(regex).length) {
    return undefined;
  }
  return {
    require_present,
    deny_present,
    exact,
    regex,
  };
}

function sanitizeQuery(value?: PolicyTlsHttpQueryMatch): PolicyTlsHttpQueryMatch | undefined {
  if (!value) return undefined;
  const keys_present = (value.keys_present ?? []).map((v) => v.trim()).filter(Boolean);
  const key_values_exact: Record<string, string[]> = {};
  for (const [k, vals] of Object.entries(value.key_values_exact ?? {})) {
    const key = k.trim();
    const cleaned = (vals ?? []).map((v) => v.trim()).filter(Boolean);
    if (key && cleaned.length) key_values_exact[key] = cleaned;
  }
  const key_values_regex: Record<string, string> = {};
  for (const [k, pattern] of Object.entries(value.key_values_regex ?? {})) {
    const key = k.trim();
    const cleaned = pattern.trim();
    if (key && cleaned) key_values_regex[key] = cleaned;
  }
  if (!keys_present.length && !Object.keys(key_values_exact).length && !Object.keys(key_values_regex).length) {
    return undefined;
  }
  return {
    keys_present,
    key_values_exact,
    key_values_regex,
  };
}

function sanitizePath(value?: PolicyTlsHttpPathMatch): PolicyTlsHttpPathMatch | undefined {
  if (!value) return undefined;
  const exact = (value.exact ?? []).map((v) => v.trim()).filter(Boolean);
  const prefix = (value.prefix ?? []).map((v) => v.trim()).filter(Boolean);
  const regex = value.regex?.trim();
  if (!exact.length && !prefix.length && !regex) return undefined;
  return {
    exact,
    prefix,
    ...(regex ? { regex } : {}),
  };
}

function sanitizeHttpRequest(value?: PolicyTlsHttpRequest): PolicyTlsHttpRequest | undefined {
  if (!value) return undefined;
  const host = sanitizeTlsNameMatch(value.host);
  const methods = (value.methods ?? []).map((v) => v.trim().toUpperCase()).filter(Boolean);
  const path = sanitizePath(value.path);
  const query = sanitizeQuery(value.query);
  const headers = sanitizeHeaders(value.headers);
  if (!host && !methods.length && !path && !query && !headers) return undefined;
  return {
    ...(host ? { host } : {}),
    ...(methods.length ? { methods } : {}),
    ...(path ? { path } : {}),
    ...(query ? { query } : {}),
    ...(headers ? { headers } : {}),
  };
}

function sanitizeHttpResponse(value?: PolicyTlsHttpResponse): PolicyTlsHttpResponse | undefined {
  if (!value) return undefined;
  const headers = sanitizeHeaders(value.headers);
  if (!headers) return undefined;
  return { headers };
}

function sanitizeHttp(value?: PolicyTlsHttpPolicy): PolicyTlsHttpPolicy | undefined {
  if (!value) return undefined;
  const request = sanitizeHttpRequest(value.request);
  const response = sanitizeHttpResponse(value.response);
  if (!request && !response) return undefined;
  return {
    ...(request ? { request } : {}),
    ...(response ? { response } : {}),
  };
}

function sanitizeTls(value?: PolicyTlsMatch): PolicyTlsMatch | undefined {
  if (!value) return undefined;
  const mode = value.mode ?? 'metadata';
  const sni = sanitizeTlsNameMatch(value.sni);
  const server_san = sanitizeTlsNameMatch(value.server_san);
  const server_cn = sanitizeTlsNameMatch(value.server_cn);
  const server_dn = value.server_dn?.trim();
  const fingerprint_sha256 = (value.fingerprint_sha256 ?? []).map((v) => v.trim()).filter(Boolean);
  const trust_anchors_pem = (value.trust_anchors_pem ?? []).map((v) => v.trim()).filter(Boolean);
  const tls13_uninspectable = value.tls13_uninspectable ?? 'deny';
  const http = sanitizeHttp(value.http);

  const hasAny =
    mode !== 'metadata' ||
    !!sni ||
    !!server_san ||
    !!server_cn ||
    !!server_dn ||
    fingerprint_sha256.length > 0 ||
    trust_anchors_pem.length > 0 ||
    tls13_uninspectable !== 'deny' ||
    !!http;
  if (!hasAny) return undefined;

  const out: PolicyTlsMatch = {
    mode,
    ...(sni ? { sni } : {}),
    ...(server_dn ? { server_dn } : {}),
    ...(server_san ? { server_san } : {}),
    ...(server_cn ? { server_cn } : {}),
    ...(fingerprint_sha256.length ? { fingerprint_sha256 } : {}),
    ...(trust_anchors_pem.length ? { trust_anchors_pem } : {}),
    ...(tls13_uninspectable ? { tls13_uninspectable } : {}),
    ...(http ? { http } : {}),
  };

  if (!isTlsNameMatchEmpty(out.sni) && !out.sni) delete out.sni;
  return out;
}

export function sanitizePolicyRequestForApi(value: PolicyCreateRequest): PolicyCreateRequest {
  const out: PolicyCreateRequest = {
    mode: value.mode,
    policy: {
      source_groups: [],
    },
  };

  if (value.policy.default_policy) {
    out.policy.default_policy = value.policy.default_policy;
  }

  for (const group of value.policy.source_groups ?? []) {
    const sources: PolicySources = {
      cidrs: (group.sources?.cidrs ?? []).map((v) => v.trim()).filter(Boolean),
      ips: (group.sources?.ips ?? []).map((v) => v.trim()).filter(Boolean),
      kubernetes: [],
    };
    for (const source of group.sources?.kubernetes ?? []) {
      const integration = source.integration.trim();
      const pod_selector = source.pod_selector
        ? {
            namespace: source.pod_selector.namespace.trim(),
            match_labels: asStringMap(source.pod_selector.match_labels),
          }
        : undefined;
      const node_selector = source.node_selector
        ? {
            match_labels: asStringMap(source.node_selector.match_labels),
          }
        : undefined;

      if (!integration && !pod_selector && !node_selector) continue;
      const normalizedSource: PolicyKubernetesSource = {
        integration,
      };
      if (pod_selector) normalizedSource.pod_selector = pod_selector;
      if (node_selector) normalizedSource.node_selector = node_selector;
      sources.kubernetes.push(normalizedSource);
    }

    const rules: PolicyRule[] = [];
    for (const rule of group.rules ?? []) {
      const match: PolicyRuleMatch = {
        dst_cidrs: (rule.match?.dst_cidrs ?? []).map((v) => v.trim()).filter(Boolean),
        dst_ips: (rule.match?.dst_ips ?? []).map((v) => v.trim()).filter(Boolean),
        src_ports: (rule.match?.src_ports ?? []).map((v) => v.trim()).filter(Boolean),
        dst_ports: (rule.match?.dst_ports ?? []).map((v) => v.trim()).filter(Boolean),
        icmp_types: (rule.match?.icmp_types ?? []).filter((v) => Number.isFinite(v)),
        icmp_codes: (rule.match?.icmp_codes ?? []).filter((v) => Number.isFinite(v)),
      };
      const dns_hostname = rule.match?.dns_hostname?.trim();
      if (dns_hostname) match.dns_hostname = dns_hostname;
      const proto = rule.match?.proto?.trim();
      if (proto) match.proto = proto;
      const tls = sanitizeTls(rule.match?.tls);
      if (tls) match.tls = tls;

      const normalizedRule: PolicyRule = {
        id: rule.id.trim(),
        action: rule.action,
        match,
      };
      if (typeof rule.priority === 'number') normalizedRule.priority = rule.priority;
      if (rule.mode) normalizedRule.mode = rule.mode;
      rules.push(normalizedRule);
    }

    const normalizedGroup: PolicySourceGroup = {
      id: group.id.trim(),
      sources,
      rules,
    };
    if (typeof group.priority === 'number') normalizedGroup.priority = group.priority;
    if (group.default_action) normalizedGroup.default_action = group.default_action;
    out.policy.source_groups.push(normalizedGroup);
  }

  return out;
}

export function nextNamedId(prefix: string, existingIds: string[]): string {
  const seen = new Set(existingIds.map((id) => id.trim()).filter(Boolean));
  let i = 1;
  while (seen.has(`${prefix}-${i}`)) i += 1;
  return `${prefix}-${i}`;
}

