import { describe, expect, it } from 'vitest';

import type { AuditFinding, ThreatFinding } from '../../types';
import { auditFindingKey, buildAuditThreatAnnotations } from './threatAnnotations';

function auditFinding(overrides: Partial<AuditFinding> = {}): AuditFinding {
  return {
    finding_type: 'dns_deny',
    policy_id: null,
    source_group: 'workstations',
    hostname: 'bad.example.com',
    dst_ip: null,
    dst_port: null,
    proto: null,
    fqdn: null,
    sni: null,
    icmp_type: null,
    icmp_code: null,
    query_type: null,
    first_seen: 1_700_000_000,
    last_seen: 1_700_000_010,
    count: 2,
    node_ids: ['node-a'],
    ...overrides,
  };
}

function threatFinding(overrides: Partial<ThreatFinding> = {}): ThreatFinding {
  return {
    indicator: 'bad.example.com',
    indicator_type: 'hostname',
    observation_layer: 'dns',
    match_source: 'stream',
    source_group: 'workstations',
    severity: 'high',
    confidence: 70,
    feed_hits: [{ feed: 'threatfox', severity: 'high', confidence: 70, reference_url: null, tags: [] }],
    first_seen: 1_700_000_000,
    last_seen: 1_700_000_010,
    count: 1,
    sample_node_ids: ['node-a'],
    alertable: true,
    audit_links: ['dns:none:workstations:bad.example.com'],
    enrichment_status: 'completed',
    ...overrides,
  };
}

describe('audit threat annotations', () => {
  it('derives the same audit key shape used by threat links', () => {
    expect(auditFindingKey(auditFinding())).toBe('dns:none:workstations:bad.example.com');
  });

  it('aggregates overlapping threat findings by effective severity and deep link', () => {
    const finding = auditFinding();
    const annotations = buildAuditThreatAnnotations([finding], [
      threatFinding(),
      threatFinding({
        severity: 'critical',
        audit_links: ['dns:none:workstations:bad.example.com'],
      }),
    ]);

    expect(annotations[auditFindingKey(finding)]).toEqual({
      severity: 'critical',
      matchCount: 2,
      href: '/threats?audit_key=dns%3Anone%3Aworkstations%3Abad.example.com',
    });
  });
});
