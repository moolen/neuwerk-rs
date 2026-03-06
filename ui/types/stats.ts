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
  node_count: number;
  follower_count: number;
  followers_caught_up: number;
  nodes: ClusterNodeCatchup[];
}

export interface ClusterNodeCatchup {
  node_id: string;
  addr: string;
  role: 'leader' | 'follower';
  matched_index: number | null;
  lag_entries: number | null;
  caught_up: boolean;
}

export interface StatsResponse {
  dataplane: DataplaneStats;
  dns: DnsStats;
  tls: TlsStats;
  dhcp: DhcpStats;
  cluster: ClusterStats;
}
