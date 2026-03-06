import { describe, expect, it } from 'vitest';

import { normalizePolicyRequest } from './normalize';

describe('policyModel normalize', () => {
  it('returns empty policy request for non-object input', () => {
    const normalized = normalizePolicyRequest(null);
    expect(normalized).toEqual({
      name: '',
      mode: 'enforce',
      policy: { default_policy: 'deny', source_groups: [] },
    });
  });

  it('normalizes proto numbers and trims string lists', () => {
    const normalized = normalizePolicyRequest({
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: { cidrs: [' 10.0.0.0/24 '], ips: [' 1.1.1.1 '], kubernetes: [] },
            rules: [
              {
                id: 'r1',
                action: 'allow',
                match: {
                  proto: 6,
                  dst_ports: [' 443 '],
                  src_ports: [],
                  dst_cidrs: [],
                  dst_ips: [],
                  icmp_types: [],
                  icmp_codes: [],
                },
              },
            ],
          },
        ],
      },
    });

    expect(normalized.policy.source_groups[0].rules[0].match.proto).toBe('6');
    expect(normalized.policy.source_groups[0].rules[0].match.dst_ports).toEqual(['443']);
    expect(normalized.policy.source_groups[0].sources.cidrs).toEqual(['10.0.0.0/24']);
    expect(normalized.policy.source_groups[0].sources.ips).toEqual(['1.1.1.1']);
  });

  it('filters invalid kubernetes sources', () => {
    const normalized = normalizePolicyRequest({
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: {
              cidrs: [],
              ips: [],
              kubernetes: [
                {},
                { integration: 'k8s-a' },
                { pod_selector: { namespace: 'default', match_labels: { app: 'api' } } },
              ],
            },
            rules: [],
          },
        ],
      },
    });

    expect(normalized.policy.source_groups[0].sources.kubernetes).toEqual([
      { integration: 'k8s-a' },
      {
        integration: '',
        pod_selector: { namespace: 'default', match_labels: { app: 'api' } },
      },
    ]);
  });

  it('normalizes TLS HTTP methods and preserves matcher sections', () => {
    const normalized = normalizePolicyRequest({
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: { cidrs: [], ips: [], kubernetes: [] },
            rules: [
              {
                id: 'r1',
                action: 'allow',
                match: {
                  dst_cidrs: [],
                  dst_ips: [],
                  src_ports: [],
                  dst_ports: [],
                  icmp_types: [],
                  icmp_codes: [],
                  tls: {
                    mode: 'intercept',
                    http: {
                      request: {
                        methods: ['get', 'post'],
                        path: { prefix: ['/v1/'] },
                      },
                    },
                  },
                },
              },
            ],
          },
        ],
      },
    });

    const tls = normalized.policy.source_groups[0].rules[0].match.tls;
    expect(tls?.mode).toBe('intercept');
    expect(tls?.http?.request?.methods).toEqual(['GET', 'POST']);
    expect(tls?.http?.request?.path?.prefix).toEqual(['/v1/']);
  });

  it('drops empty tls object from rule match', () => {
    const normalized = normalizePolicyRequest({
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: { cidrs: [], ips: [], kubernetes: [] },
            rules: [
              {
                id: 'r1',
                action: 'allow',
                match: {
                  dst_cidrs: [],
                  dst_ips: [],
                  src_ports: [],
                  dst_ports: [],
                  icmp_types: [],
                  icmp_codes: [],
                  tls: {},
                },
              },
            ],
          },
        ],
      },
    });

    expect(normalized.policy.source_groups[0].rules[0].match.tls).toBeUndefined();
  });
});
