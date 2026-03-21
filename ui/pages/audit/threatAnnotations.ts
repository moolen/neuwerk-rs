import type { AuditFinding, ThreatFinding, ThreatSeverity } from '../../types';

export interface AuditThreatAnnotation {
  severity: ThreatSeverity;
  matchCount: number;
  href: string;
}

const SEVERITY_ORDER: Record<ThreatSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function normalizeText(value: string | null | undefined): string {
  return (value ?? '').trim().replace(/\.+$/, '').toLowerCase();
}

export function auditFindingKey(finding: AuditFinding): string {
  const policyId = finding.policy_id ?? 'none';

  switch (finding.finding_type) {
    case 'dns_deny':
      return `dns:${policyId}:${finding.source_group}:${normalizeText(finding.hostname)}`;
    case 'l4_deny':
      return `l4:${policyId}:${finding.source_group}:${finding.dst_ip ?? '0.0.0.0'}:${finding.dst_port ?? 0}:${finding.proto ?? 0}:${normalizeText(finding.fqdn)}`;
    case 'tls_deny':
      return `tls:${policyId}:${finding.source_group}:${normalizeText(finding.sni)}:${finding.dst_ip ?? '0.0.0.0'}:${finding.dst_port ?? 0}`;
    case 'icmp_deny':
      return `icmp:${policyId}:${finding.source_group}:${finding.dst_ip ?? '0.0.0.0'}:${finding.icmp_type ?? 255}:${finding.icmp_code ?? 255}`;
  }
}

export function buildAuditThreatAnnotations(
  auditFindings: AuditFinding[],
  threatFindings: ThreatFinding[],
): Record<string, AuditThreatAnnotation> {
  const annotations = new Map<string, AuditThreatAnnotation>();
  const auditKeys = new Set(auditFindings.map((item) => auditFindingKey(item)));

  for (const item of threatFindings) {
    for (const auditLink of item.audit_links) {
      if (!auditKeys.has(auditLink)) {
        continue;
      }
      const existing = annotations.get(auditLink);
      const severity =
        existing && SEVERITY_ORDER[existing.severity] >= SEVERITY_ORDER[item.severity]
          ? existing.severity
          : item.severity;
      annotations.set(auditLink, {
        severity,
        matchCount: (existing?.matchCount ?? 0) + 1,
        href: `/threats?audit_key=${encodeURIComponent(auditLink)}`,
      });
    }
  }

  return Object.fromEntries(annotations);
}
