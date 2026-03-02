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
  mode: PolicyMode;
  policy: PolicyConfig;
}

export interface PolicyCreateRequest {
  mode: PolicyMode;
  policy: PolicyConfig;
}

export type IntegrationKind = 'kubernetes';

export interface IntegrationView {
  id: string;
  created_at: string;
  name: string;
  kind: IntegrationKind;
  api_server_url: string;
  ca_cert_pem: string;
  auth_type: string;
  token_configured: boolean;
}

export interface IntegrationCreateRequest {
  name: string;
  kind: IntegrationKind;
  api_server_url: string;
  ca_cert_pem: string;
  service_account_token: string;
}

export interface IntegrationUpdateRequest {
  api_server_url: string;
  ca_cert_pem: string;
  service_account_token: string;
}

export interface DecisionCounters {
  allow: number;
  deny: number;
  pending_tls: number;
}

export interface DataplaneStats {
  active_flows: number;
  active_nat_entries: number;
  nat_port_utilization: number;
  packets: DecisionCounters;
  bytes: DecisionCounters;
  flows_opened: number;
  flows_closed: number;
  ipv4_fragments_dropped: number;
  ipv4_ttl_exceeded: number;
}

export interface DnsStats {
  queries_allow: number;
  queries_deny: number;
  nxdomain_policy: number;
  nxdomain_upstream: number;
}

export interface TlsStats {
  allow: number;
  deny: number;
}

export interface DhcpStats {
  lease_active: boolean;
  lease_expiry_epoch: number;
}

export interface ClusterStats {
  is_leader: boolean;
  current_term: number;
  last_log_index: number;
  last_applied: number;
}

export interface StatsResponse {
  dataplane: DataplaneStats;
  dns: DnsStats;
  tls: TlsStats;
  dhcp: DhcpStats;
  cluster: ClusterStats;
}

export interface DNSCacheEntry {
  hostname: string;
  ips: string[];
  last_seen: number;
}

export interface DNSCacheResponse {
  entries: DNSCacheEntry[];
}

export interface WiretapEvent {
  event_type?: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: number;
  packets_in: number;
  packets_out: number;
  last_seen: number;
  hostname?: string | null;
  node_id: string;
}

export type AuditFindingType = 'dns_deny' | 'l4_deny' | 'tls_deny' | 'icmp_deny';

export interface AuditFinding {
  finding_type: AuditFindingType;
  policy_id?: string | null;
  source_group: string;
  hostname?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  proto?: number | null;
  fqdn?: string | null;
  sni?: string | null;
  icmp_type?: number | null;
  icmp_code?: number | null;
  query_type?: number | null;
  first_seen: number;
  last_seen: number;
  count: number;
  node_ids: string[];
}

export interface AuditNodeError {
  node_id: string;
  error: string;
}

export interface AuditQueryResponse {
  items: AuditFinding[];
  partial: boolean;
  node_errors: AuditNodeError[];
  nodes_queried: number;
  nodes_responded: number;
}

export interface AuthUser {
  sub: string;
  sa_id?: string | null;
  exp?: number | null;
  roles: string[];
}

export type ServiceAccountStatus = 'active' | 'disabled';
export type ServiceAccountTokenStatus = 'active' | 'revoked';

export interface ServiceAccount {
  id: string;
  name: string;
  description?: string | null;
  created_at: string;
  created_by: string;
  status: ServiceAccountStatus;
}

export interface ServiceAccountToken {
  id: string;
  service_account_id: string;
  name?: string | null;
  created_at: string;
  created_by: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  last_used_at?: string | null;
  kid: string;
  status: ServiceAccountTokenStatus;
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string | null;
}

export interface CreateServiceAccountTokenRequest {
  name?: string;
  ttl?: string;
  eternal?: boolean;
}

export interface CreateServiceAccountTokenResponse {
  token: string;
  token_meta: ServiceAccountToken;
}

export interface TlsInterceptCaStatus {
  configured: boolean;
  source?: 'local' | 'cluster' | null;
  fingerprint_sha256?: string | null;
}
