import type { WiretapEvent } from '../../../types';

export const LIVE_TABLE_COLUMNS = [
  'Flow',
  'Proto',
  'Packets In',
  'Packets Out',
  'Hostname',
  'Last Seen',
] as const;

export function formatLiveFlowLabel(event: WiretapEvent): string {
  return `${event.src_ip}:${event.src_port} -> ${event.dst_ip}:${event.dst_port}`;
}

export function formatLiveHostname(hostname?: string | null): string {
  const trimmed = hostname?.trim();
  if (!trimmed) {
    return '-';
  }
  return trimmed;
}
