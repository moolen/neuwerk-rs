export type PolicyMode = 'disabled' | 'audit' | 'enforce';

export type PolicyConfig = Record<string, unknown>;

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
