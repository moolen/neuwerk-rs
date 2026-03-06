import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../../types';
import { mutateRuleMatch } from './ruleMatchDraft';

function makeDraft(withRule = true): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_action: 'allow',
      source_groups: [
        {
          id: 'g1',
          priority: 100,
          default_action: 'allow',
          sources: [{ cidrs: ['10.0.0.0/24'] }],
          rules: withRule
            ? [
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
                  },
                },
              ]
            : [],
        },
      ],
    },
  };
}

describe('ruleMatchDraft', () => {
  it('mutates an existing rule match', () => {
    const draft = makeDraft(true);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    mutateRuleMatch(updateDraft, 0, 0, (match) => {
      match.proto = 'tcp';
    });

    expect(draft.policy.source_groups[0].rules[0].match.proto).toBe('tcp');
  });

  it('is a no-op for missing rule entries', () => {
    const draft = makeDraft(false);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    expect(() =>
      mutateRuleMatch(updateDraft, 0, 0, (match) => {
        match.proto = 'udp';
      })
    ).not.toThrow();
  });
});
