import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { AuditFinding } from '../../../types';
import { AuditFindingsTable } from './AuditFindingsTable';

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

describe('AuditFindingsTable', () => {
  it('renders threat annotations with severity and deep link', () => {
    const html = renderToStaticMarkup(
      <AuditFindingsTable
        items={[auditFinding()]}
        threatAnnotations={{
          'dns:none:workstations:bad.example.com': {
            severity: 'critical',
            matchCount: 2,
            href: '/threats?audit_key=dns%3Anone%3Aworkstations%3Abad.example.com',
          },
        }}
      />,
    );

    expect(html).toContain('Threat');
    expect(html).toContain('critical');
    expect(html).toContain('/threats?audit_key=dns%3Anone%3Aworkstations%3Abad.example.com');
  });
});
