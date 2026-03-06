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
