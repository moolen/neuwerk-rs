import type { AggregatedFlow } from '../types';

export const AGGREGATED_TABLE_COLUMNS = [
  'Flow Pair',
  'Proto',
  'Flows',
  'Packets In',
  'Packets Out',
  'Hostname',
  'Last Seen',
] as const;

export function formatAggregatedFlowPair(flow: AggregatedFlow): string {
  return `${flow.src_ip} -> ${flow.dst_ip}`;
}

export function formatAggregatedHostname(hostname?: string | null): string {
  const trimmed = hostname?.trim();
  if (!trimmed) {
    return '-';
  }
  return trimmed;
}
