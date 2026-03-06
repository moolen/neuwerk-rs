import type { AuditFinding } from '../../types';

export function formatAuditTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

export function formatAuditDestination(item: AuditFinding): string {
  return item.dst_ip ? `${item.dst_ip}${item.dst_port ? `:${item.dst_port}` : ''}` : item.hostname || '-';
}

export function formatAuditSignals(item: AuditFinding): string {
  if (item.fqdn) return item.fqdn;
  if (item.sni) return item.sni;
  if (item.icmp_type !== null && item.icmp_type !== undefined) {
    return `icmp ${item.icmp_type}/${item.icmp_code ?? '-'}`;
  }
  return '-';
}
