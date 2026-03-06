export type PolicyMode = 'disabled' | 'audit' | 'enforce';

export type PolicyAction = 'allow' | 'deny';
export type PolicyRuleMode = 'audit' | 'enforce';
export type PolicyTlsMode = 'metadata' | 'intercept';
export type PolicyTls13Uninspectable = 'allow' | 'deny';

export interface PolicyConfig {
  default_policy?: PolicyAction;
  source_groups: PolicySourceGroup[];
}

export interface PolicySourceGroup {
  id: string;
  priority?: number;
  sources: PolicySources;
  rules: PolicyRule[];
  default_action?: PolicyAction;
}

export interface PolicySources {
  cidrs: string[];
  ips: string[];
  kubernetes: PolicyKubernetesSource[];
}

export interface PolicyKubernetesSource {
  integration: string;
  pod_selector?: PolicyKubernetesPodSelector;
  node_selector?: PolicyKubernetesNodeSelector;
}

export interface PolicyKubernetesPodSelector {
  namespace: string;
  match_labels: Record<string, string>;
}

export interface PolicyKubernetesNodeSelector {
  match_labels: Record<string, string>;
}

export interface PolicyRule {
  id: string;
  priority?: number;
  action: PolicyAction;
  mode?: PolicyRuleMode;
  match: PolicyRuleMatch;
}

export interface PolicyRuleMatch {
  dst_cidrs: string[];
  dst_ips: string[];
  dns_hostname?: string;
  proto?: string;
  src_ports: string[];
  dst_ports: string[];
  icmp_types: number[];
  icmp_codes: number[];
  tls?: PolicyTlsMatch;
}

export interface PolicyTlsNameMatch {
  exact: string[];
  regex?: string;
}

export interface PolicyTlsMatch {
  mode?: PolicyTlsMode;
  sni?: PolicyTlsNameMatch;
  server_dn?: string;
  server_san?: PolicyTlsNameMatch;
  server_cn?: PolicyTlsNameMatch;
  fingerprint_sha256: string[];
  trust_anchors_pem: string[];
  tls13_uninspectable?: PolicyTls13Uninspectable;
  http?: PolicyTlsHttpPolicy;
}

export interface PolicyTlsHttpPolicy {
  request?: PolicyTlsHttpRequest;
  response?: PolicyTlsHttpResponse;
}

export interface PolicyTlsHttpRequest {
  host?: PolicyTlsNameMatch;
  methods: string[];
  path?: PolicyTlsHttpPathMatch;
  query?: PolicyTlsHttpQueryMatch;
  headers?: PolicyTlsHttpHeadersMatch;
}

export interface PolicyTlsHttpResponse {
  headers?: PolicyTlsHttpHeadersMatch;
}

export interface PolicyTlsHttpPathMatch {
  exact: string[];
  prefix: string[];
  regex?: string;
}

export interface PolicyTlsHttpQueryMatch {
  keys_present: string[];
  key_values_exact: Record<string, string[]>;
  key_values_regex: Record<string, string>;
}

export interface PolicyTlsHttpHeadersMatch {
  require_present: string[];
  deny_present: string[];
  exact: Record<string, string[]>;
  regex: Record<string, string>;
}

export interface PolicyRecord {
  id: string;
  created_at: string;
  name?: string;
  mode: PolicyMode;
  policy: PolicyConfig;
}

export interface PolicyCreateRequest {
  name?: string;
  mode: PolicyMode;
  policy: PolicyConfig;
}
