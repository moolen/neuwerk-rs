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
