import { describe, expect, it } from 'vitest';

import type { PolicyRule, PolicyRuleMatch } from '../../types';
import { validateRuleBasics, validateRuleMatchCore } from './ruleMatchValidation';

interface Issue {
  path: string;
  message: string;
}

function baseRule(): PolicyRule {
  return {
    id: 'rule-1',
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
  };
}

function baseMatch(): PolicyRuleMatch {
  return {
    dst_cidrs: [],
    dst_ips: [],
    src_ports: [],
    dst_ports: [],
    icmp_types: [],
    icmp_codes: [],
  };
}

describe('ruleMatchValidation', () => {
  it('validates rule basics', () => {
    const issues: Issue[] = [];
    const rule = baseRule();
    rule.id = ' ';
    rule.priority = -1;
    rule.mode = 'bad' as PolicyRule['mode'];
    rule.action = 'weird' as PolicyRule['action'];
    validateRuleBasics(rule, 'policy.source_groups[0].rules[0]', issues);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].id' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].priority' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].action' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].mode' }),
      ]),
    );
  });

  it('validates proto, ports, dns regex, and icmp constraints', () => {
    const issues: Issue[] = [];
    const match = baseMatch();
    match.proto = '999';
    match.dns_hostname = '[';
    match.src_ports = ['70000'];
    match.dst_ports = ['0'];
    match.icmp_types = [-1];
    match.icmp_codes = [256];
    validateRuleMatchCore(match, 'policy.source_groups[0].rules[0]', issues);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.proto' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.dns_hostname' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.src_ports[0]' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.dst_ports[0]' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.icmp_types[0]' }),
        expect.objectContaining({ path: 'policy.source_groups[0].rules[0].match.icmp_codes[0]' }),
      ]),
    );
  });

  it('returns normalized protocol value for downstream tls validation', () => {
    const issues: Issue[] = [];
    const match = baseMatch();
    match.proto = ' TCP ';
    const proto = validateRuleMatchCore(match, 'policy.source_groups[0].rules[0]', issues);
    expect(proto).toBe('tcp');
    expect(issues).toEqual([]);
  });
});
