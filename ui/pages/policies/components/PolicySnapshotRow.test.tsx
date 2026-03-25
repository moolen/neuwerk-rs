import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { PolicyRecord } from '../../../types';
import { summarizePolicySources } from './policySnapshotHelpers';
import { PolicySnapshotRow } from './PolicySnapshotRow';

describe('PolicySnapshotRow', () => {
  it('renders a compact snapshot row without secondary summary cards or action buttons', () => {
    const policy: PolicyRecord = {
      id: 'abcdef123456',
      name: 'Office Egress',
      created_at: '2026-03-05T12:34:56.000Z',
      mode: 'audit',
      policy: {
        default_policy: 'allow',
        source_groups: [
          {
            id: 'homenet',
            priority: 0,
            default_action: 'allow',
            sources: {
              cidrs: ['192.168.178.0/24'],
              ips: [],
              kubernetes: [],
            },
            rules: [
              {
                id: 'rule-1',
                action: 'allow',
                mode: 'audit',
                match: {
                  dst_cidrs: ['0.0.0.0/0'],
                  dst_ips: [],
                  dns_hostname: 'github.com',
                  src_ports: [],
                  dst_ports: ['443'],
                  icmp_types: [],
                  icmp_codes: [],
                  tls: null,
                },
              },
            ],
          },
        ],
      },
    };

    const html = renderToStaticMarkup(
      <PolicySnapshotRow
        policy={policy}
        selectedId={policy.id}
        onSelect={vi.fn()}
      />,
    );

    expect(html).toContain('Office Egress');
    expect(html).not.toContain('Snapshot abcdef12');
    expect(html).toContain('audit');
    expect(html).toContain('linear-gradient(145deg, rgba(79,110,247,0.14), rgba(79,110,247,0.05))');
    expect(html).toContain('border:1px solid rgba(79,110,247,0.22)');
    expect(html).toContain('box-shadow:var(--shadow-glass)');
    expect(html).not.toContain('Source scope');
    expect(html).not.toContain('Target profile');
    expect(html).not.toContain('grid grid-cols-3 gap-2');
    expect(html).not.toContain('Open');
    expect(html).not.toContain('Delete');
  });

  it('keeps policy-level source assumptions that are insufficient for group-centric rows', () => {
    const policy: PolicyRecord = {
      id: 'policy-1',
      name: 'Two groups',
      created_at: '2026-03-05T12:34:56.000Z',
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'apps',
            sources: {
              cidrs: ['10.0.0.0/24'],
              ips: ['192.168.1.10'],
              kubernetes: [],
            },
            rules: [],
          },
          {
            id: 'batch',
            sources: {
              cidrs: ['10.0.1.0/24'],
              ips: ['192.168.2.10'],
              kubernetes: [],
            },
            rules: [],
          },
        ],
      },
    };

    // Existing snapshot helpers flatten policy records and drop non-CIDR source detail.
    expect(summarizePolicySources(policy)).toBe('10.0.0.0/24, 10.0.1.0/24');
  });
});
