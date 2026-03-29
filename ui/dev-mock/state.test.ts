import { describe, expect, it } from 'vitest';

import { createMockState } from './state';

describe('createMockState', () => {
  it('seeds realistic read models with stable timestamps and identifiers', () => {
    const now = 1_710_000_000_000;
    const state = createMockState(now);

    expect(state.authUser).toMatchObject({
      sub: 'local-preview-admin',
      roles: ['admin'],
    });

    expect(state.stats).toMatchObject({
      dataplane: {
        active_flows: expect.any(Number),
        packets: {
          allow: expect.any(Number),
          deny: expect.any(Number),
          pending_tls: expect.any(Number),
        },
      },
      dns: {
        queries_allow: expect.any(Number),
      },
      cluster: {
        node_count: expect.any(Number),
        nodes: expect.arrayContaining([
          expect.objectContaining({
            node_id: expect.stringMatching(/^node-/),
          }),
        ]),
      },
    });

    expect(state.dnsCache.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          hostname: expect.any(String),
          ips: expect.arrayContaining([expect.any(String)]),
          last_seen: expect.any(Number),
        }),
      ])
    );

    expect(state.auditFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          finding_type: 'dns_deny',
          source_group: expect.any(String),
          first_seen: expect.any(Number),
          last_seen: expect.any(Number),
        }),
      ])
    );

    expect(state.threatFindings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          indicator: expect.any(String),
          severity: expect.stringMatching(/low|medium|high|critical/),
          feed_hits: expect.arrayContaining([
            expect.objectContaining({
              feed: expect.any(String),
            }),
          ]),
        }),
      ])
    );

    expect(state.ssoSupportedProviders.map((provider) => provider.id).sort()).toEqual([
      'generic-oidc',
      'github',
      'google',
    ]);

    expect(state.threatSilences[0]).toMatchObject({
      id: 'silence-001',
      created_at: Math.floor(now / 1000) - 3600,
    });
  });

  it('seeds dns audit linkage keys in the same contract shape used by the audit page', () => {
    const state = createMockState(1_710_000_000_000);
    const dnsFinding = state.auditFindings.find((item) => item.finding_type === 'dns_deny');
    const linkedThreat = state.threatFindings.find((item) =>
      item.audit_links.includes('dns:policy-egress-dns:branch-office:malware-update.bad')
    );

    expect(dnsFinding).toMatchObject({
      finding_type: 'dns_deny',
      policy_id: 'policy-egress-dns',
      source_group: 'branch-office',
      hostname: 'malware-update.bad',
    });
    expect(linkedThreat).toBeDefined();
  });
});
