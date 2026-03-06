import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../types';
import { sanitizePolicyRequestForApi } from './sanitize';

function emptyRequest(): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      source_groups: [],
    },
  };
}

describe('policyModel sanitize', () => {
  it('trims source/rule fields and filters empty kubernetes sources', () => {
    const request: PolicyCreateRequest = {
      mode: 'enforce',
      policy: {
        default_policy: 'allow',
        source_groups: [
          {
            id: '  group-1  ',
            sources: {
              cidrs: [' 10.0.0.0/24 ', '  '],
              ips: [' 1.1.1.1 ', ''],
              kubernetes: [
                { integration: '   ' },
                {
                  integration: '  k8s-a  ',
                  pod_selector: {
                    namespace: ' default ',
                    match_labels: {
                      ' app ': ' api ',
                      empty: '  ',
                    } as unknown as Record<string, string>,
                  },
                },
              ],
            },
            rules: [
              {
                id: '  rule-1 ',
                action: 'allow',
                mode: 'audit',
                match: {
                  dst_cidrs: [' 192.168.0.0/16 ', ''],
                  dst_ips: [' 8.8.8.8 ', '  '],
                  dns_hostname: ' example.com ',
                  proto: ' tcp ',
                  src_ports: [' 12345 ', ''],
                  dst_ports: [' 443 '],
                  icmp_types: [8, Number.NaN],
                  icmp_codes: [0, Number.POSITIVE_INFINITY],
                  tls: undefined,
                },
              },
            ],
          },
        ],
      },
    };

    const sanitized = sanitizePolicyRequestForApi(request);

    expect(sanitized).toEqual({
      mode: 'enforce',
      policy: {
        default_policy: 'allow',
        source_groups: [
          {
            id: 'group-1',
            sources: {
              cidrs: ['10.0.0.0/24'],
              ips: ['1.1.1.1'],
              kubernetes: [
                {
                  integration: 'k8s-a',
                  pod_selector: {
                    namespace: 'default',
                    match_labels: { app: 'api' },
                  },
                },
              ],
            },
            rules: [
              {
                id: 'rule-1',
                action: 'allow',
                mode: 'audit',
                match: {
                  dst_cidrs: ['192.168.0.0/16'],
                  dst_ips: ['8.8.8.8'],
                  dns_hostname: 'example.com',
                  proto: 'tcp',
                  src_ports: ['12345'],
                  dst_ports: ['443'],
                  icmp_types: [8],
                  icmp_codes: [0],
                },
              },
            ],
          },
        ],
      },
    });
  });

  it('keeps selector-based kubernetes sources even when selector values become empty', () => {
    const request: PolicyCreateRequest = {
      ...emptyRequest(),
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: {
              cidrs: [],
              ips: [],
              kubernetes: [
                {
                  integration: ' ',
                  pod_selector: {
                    namespace: ' ',
                    match_labels: { empty: ' ' } as unknown as Record<string, string>,
                  },
                },
              ],
            },
            rules: [],
          },
        ],
      },
    };

    const sanitized = sanitizePolicyRequestForApi(request);
    expect(sanitized.policy.source_groups[0].sources.kubernetes).toEqual([
      {
        integration: '',
        pod_selector: {
          namespace: '',
          match_labels: {},
        },
      },
    ]);
  });

  it('drops tls when only default/empty tls fields are provided', () => {
    const request: PolicyCreateRequest = {
      ...emptyRequest(),
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
                    mode: 'metadata',
                    sni: { exact: ['  '], regex: ' ' },
                    server_san: { exact: [] },
                    server_cn: { exact: [''] },
                    server_dn: ' ',
                    fingerprint_sha256: [' '],
                    trust_anchors_pem: [' '],
                    tls13_uninspectable: 'deny',
                    http: {
                      request: {
                        methods: [' '],
                        path: { exact: [' '], prefix: [' '] },
                        query: {
                          keys_present: [' '],
                          key_values_exact: { key: [' '] },
                          key_values_regex: { key: ' ' },
                        },
                        headers: {
                          require_present: [' '],
                          deny_present: [' '],
                          exact: { key: [' '] },
                          regex: { key: ' ' },
                        },
                      },
                      response: {
                        headers: {
                          require_present: [' '],
                          deny_present: [' '],
                          exact: { key: [' '] },
                          regex: { key: ' ' },
                        },
                      },
                    },
                  },
                },
              },
            ],
          },
        ],
      },
    };

    const sanitized = sanitizePolicyRequestForApi(request);
    expect(sanitized.policy.source_groups[0].rules[0].match.tls).toBeUndefined();
  });

  it('sanitizes tls/http matchers and uppercases methods', () => {
    const request: PolicyCreateRequest = {
      ...emptyRequest(),
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
                    sni: { exact: [' foo.example ', ''], regex: ' ^foo\\.example$ ' },
                    server_san: { exact: [' bar.example '] },
                    server_cn: { exact: [' cn.example '] },
                    server_dn: ' CN=Example ',
                    fingerprint_sha256: [' aa ', ' '],
                    trust_anchors_pem: [' pem ', ''],
                    tls13_uninspectable: 'allow',
                    http: {
                      request: {
                        host: { exact: [' svc.example '] },
                        methods: ['get', ' post '],
                        path: { exact: ['/v1'], prefix: [' /api '], regex: ' ^/health$ ' },
                        query: {
                          keys_present: [' trace '],
                          key_values_exact: { env: [' prod ', ''] },
                          key_values_regex: { version: ' ^v\\d+$ ' },
                        },
                        headers: {
                          require_present: [' x-request-id '],
                          deny_present: [' x-debug '],
                          exact: { accept: [' application/json ', ''] },
                          regex: { ' x-team ': ' ^platform$ ' },
                        },
                      },
                      response: {
                        headers: {
                          require_present: [' server '],
                          deny_present: [],
                          exact: {},
                          regex: {},
                        },
                      },
                    },
                  },
                },
              },
            ],
          },
        ],
      },
    };

    const tls = sanitizePolicyRequestForApi(request).policy.source_groups[0].rules[0].match.tls;
    expect(tls).toEqual({
      mode: 'intercept',
      sni: { exact: ['foo.example'], regex: '^foo\\.example$' },
      server_san: { exact: ['bar.example'] },
      server_cn: { exact: ['cn.example'] },
      server_dn: 'CN=Example',
      fingerprint_sha256: ['aa'],
      trust_anchors_pem: ['pem'],
      tls13_uninspectable: 'allow',
      http: {
        request: {
          host: { exact: ['svc.example'] },
          methods: ['GET', 'POST'],
          path: { exact: ['/v1'], prefix: ['/api'], regex: '^/health$' },
          query: {
            keys_present: ['trace'],
            key_values_exact: { env: ['prod'] },
            key_values_regex: { version: '^v\\d+$' },
          },
          headers: {
            require_present: ['x-request-id'],
            deny_present: ['x-debug'],
            exact: { accept: ['application/json'] },
            regex: { 'x-team': '^platform$' },
          },
        },
        response: {
          headers: {
            require_present: ['server'],
            deny_present: [],
            exact: {},
            regex: {},
          },
        },
      },
    });
  });
});
