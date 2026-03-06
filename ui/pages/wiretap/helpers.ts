import type { WiretapEvent } from '../../types';
import type { AggregatedFlow } from './types';

export const MAX_WIRETAP_EVENTS = 500;

export function filterWiretapEvents(
  events: WiretapEvent[],
  filters: { source_ip: string; dest_ip: string; hostname: string; port: string }
): WiretapEvent[] {
  return events.filter((event) => {
    if (filters.source_ip && !event.src_ip.toLowerCase().includes(filters.source_ip.toLowerCase())) {
      return false;
    }
    if (filters.dest_ip && !event.dst_ip.toLowerCase().includes(filters.dest_ip.toLowerCase())) {
      return false;
    }
    if (filters.hostname) {
      if (!event.hostname) return false;
      if (!event.hostname.toLowerCase().includes(filters.hostname.toLowerCase())) {
        return false;
      }
    }
    if (filters.port) {
      const portNum = parseInt(filters.port, 10);
      if (isNaN(portNum)) return false;
      if (event.src_port !== portNum && event.dst_port !== portNum) {
        return false;
      }
    }
    return true;
  });
}

export function aggregateWiretapFlows(events: WiretapEvent[]): AggregatedFlow[] {
  const map = new Map<string, AggregatedFlow>();
  for (const event of events) {
    const key = `${event.src_ip}|${event.dst_ip}|${event.proto}`;
    const existing = map.get(key);
    if (existing) {
      existing.flow_count += 1;
      existing.packets_in += event.packets_in;
      existing.packets_out += event.packets_out;
      existing.last_seen = Math.max(existing.last_seen, event.last_seen);
      if (event.hostname) existing.hostname = event.hostname;
    } else {
      map.set(key, {
        key,
        src_ip: event.src_ip,
        dst_ip: event.dst_ip,
        proto: event.proto,
        flow_count: 1,
        packets_in: event.packets_in,
        packets_out: event.packets_out,
        last_seen: event.last_seen,
        hostname: event.hostname,
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.last_seen - a.last_seen);
}

export function formatWiretapTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString();
}

export function wiretapProtoLabel(proto: number): string {
  switch (proto) {
    case 6:
      return 'tcp';
    case 17:
      return 'udp';
    case 1:
      return 'icmp';
    default:
      return proto.toString();
  }
}
