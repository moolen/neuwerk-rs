import { describe, expect, it } from 'vitest';

import {
  policyDisplayName,
  policyHasDpi,
  policyRuleCount,
  snapshotShortId,
  summarizePolicyDestinations,
  summarizePolicySources,
} from './policySnapshotHelpers';

describe('policySnapshotHelpers', () => {
  it('shortens ids to 8 chars', () => {
    expect(snapshotShortId('abcdef123456')).toBe('abcdef12');
    expect(snapshotShortId('short')).toBe('short');
  });

  it('derives display name from policy name with id fallback', () => {
    expect(
      policyDisplayName({
        id: 'abcdef123456',
        name: 'Office Egress',
        created_at: '2026-03-05T12:34:56.000Z',
        mode: 'enforce',
        policy: { source_groups: [] },
      }),
    ).toBe('Office Egress');

    expect(
      policyDisplayName({
        id: 'abcdef123456',
        created_at: '2026-03-05T12:34:56.000Z',
        mode: 'enforce',
        policy: { source_groups: [] },
      }),
    ).toBe('Policy abcdef12');
  });

  it('summarizes sources/destinations and DPI marker', () => {
    const policy = {
      id: 'abcdef123456',
      created_at: '2026-03-05T12:34:56.000Z',
      mode: 'audit',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: { cidrs: ['10.0.0.0/24', '192.168.1.0/24'], ips: [], kubernetes: [] },
            rules: [
              {
                id: 'r1',
                action: 'allow',
                match: {
                  dst_cidrs: ['203.0.113.0/24'],
                  dst_ips: ['198.51.100.10'],
                  dns_hostname: 'example.com',
                  src_ports: [],
                  dst_ports: [],
                  icmp_types: [],
                  icmp_codes: [],
                  tls: {
                    mode: 'intercept',
                    fingerprint_sha256: [],
                    trust_anchors_pem: [],
                  },
                },
              },
            ],
          },
        ],
      },
    };

    expect(policyRuleCount(policy)).toBe(1);
    expect(policyHasDpi(policy)).toBe(true);
    expect(summarizePolicySources(policy)).toBe('10.0.0.0/24, 192.168.1.0/24');
    expect(summarizePolicyDestinations(policy)).toBe(
      'example.com, 203.0.113.0/24, 198.51.100.10',
    );
  });

  it('caps long summaries and uses fallback labels', () => {
    const emptyPolicy = {
      id: 'abcdef123456',
      created_at: '2026-03-05T12:34:56.000Z',
      mode: 'enforce',
      policy: { source_groups: [] },
    };
    expect(summarizePolicySources(emptyPolicy)).toBe('none');
    expect(summarizePolicyDestinations(emptyPolicy)).toBe('any');

    const longPolicy = {
      id: 'abcdef123456',
      created_at: '2026-03-05T12:34:56.000Z',
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: {
              cidrs: ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24'],
              ips: [],
              kubernetes: [],
            },
            rules: [],
          },
        ],
      },
    };
    expect(summarizePolicySources(longPolicy)).toBe(
      '10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24 +1',
    );
  });
});
