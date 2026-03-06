export type ViewMode = 'live' | 'aggregated';

export interface AggregatedFlow {
  key: string;
  src_ip: string;
  dst_ip: string;
  proto: number;
  flow_count: number;
  packets_in: number;
  packets_out: number;
  last_seen: number;
  hostname?: string | null;
}
