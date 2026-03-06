import { describe, expect, it } from 'vitest';

import {
  createEmptyPolicyRequest,
  createEmptyRule,
  createEmptySourceGroup,
  createRuleTemplate,
} from './factories';

describe('policy model factories', () => {
  it('creates deterministic empty defaults', () => {
    expect(createEmptyRule('rule-42')).toEqual({
      id: 'rule-42',
      action: 'allow',
      mode: 'enforce',
      match: {
        dst_cidrs: [],
        dst_ips: [],
        src_ports: [],
        dst_ports: [],
        icmp_types: [],
        icmp_codes: [],
      },
    });

    expect(createEmptySourceGroup('group-9')).toEqual({
      id: 'group-9',
      priority: 0,
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [],
      default_action: 'deny',
    });

    expect(createEmptyPolicyRequest()).toEqual({
      name: '',
      mode: 'enforce',
      policy: {
        default_policy: 'deny',
        source_groups: [],
      },
    });
  });

  it('creates expected rule templates', () => {
    expect(createRuleTemplate('dns_allow', 'r1').match.dns_hostname).toBe('^api\\.example\\.com$');

    const l4Rule = createRuleTemplate('l4_allow', 'r2');
    expect(l4Rule.match.proto).toBe('tcp');
    expect(l4Rule.match.dst_ports).toEqual(['443']);

    const tlsMetadata = createRuleTemplate('tls_metadata', 'r3').match.tls;
    expect(tlsMetadata?.mode).toBe('metadata');
    expect(tlsMetadata?.tls13_uninspectable).toBe('deny');
    expect(tlsMetadata?.sni?.exact).toEqual(['api.example.com']);

    const tlsIntercept = createRuleTemplate('tls_intercept', 'r4').match.tls;
    expect(tlsIntercept?.mode).toBe('intercept');
    expect(tlsIntercept?.http?.request?.methods).toEqual(['GET']);
    expect(tlsIntercept?.http?.request?.path?.prefix).toEqual(['/v1/']);
  });
});
