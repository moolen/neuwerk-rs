import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { PolicyRecord } from '../../../types';
import { PolicySnapshotRow } from './PolicySnapshotRow';

describe('PolicySnapshotRow', () => {
  it('renders structured snapshot summaries instead of only chip metadata', () => {
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
        selectedId={null}
        onSelect={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    expect(html).toContain('Source scope');
    expect(html).toContain('Target profile');
    expect(html).toContain('grid grid-cols-3 gap-2');
    expect(html).toContain('Open');
  });
});
