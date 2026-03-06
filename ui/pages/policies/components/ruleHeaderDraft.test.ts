import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../../types';
import { createEmptyPolicyRequest, createEmptyRule, createEmptySourceGroup } from '../../../utils/policyModel';
import { mutateRuleHeader, parseRulePriority } from './ruleHeaderDraft';

function withSingleRuleDraft(): PolicyCreateRequest {
  const draft = createEmptyPolicyRequest();
  const group = createEmptySourceGroup('group-1');
  group.rules.push(createEmptyRule('rule-1'));
  draft.policy.source_groups.push(group);
  return draft;
}

describe('ruleHeaderDraft helpers', () => {
  it('mutates existing rule header fields', () => {
    let draft = withSingleRuleDraft();
    mutateRuleHeader(
      (mutator) => {
        const next = JSON.parse(JSON.stringify(draft)) as PolicyCreateRequest;
        mutator(next);
        draft = next;
      },
      0,
      0,
      (rule) => {
        rule.id = 'rule-a';
        rule.priority = 7;
        rule.action = 'allow';
        rule.mode = 'audit';
      },
    );

    expect(draft.policy.source_groups[0].rules[0]).toMatchObject({
      id: 'rule-a',
      priority: 7,
      action: 'allow',
      mode: 'audit',
    });
  });

  it('ignores mutation when indices are out of bounds', () => {
    const draft = withSingleRuleDraft();
    const before = JSON.parse(JSON.stringify(draft)) as PolicyCreateRequest;
    mutateRuleHeader(
      (mutator) => {
        mutator(draft);
      },
      9,
      0,
      (rule) => {
        rule.id = 'unexpected';
      },
    );
    expect(draft).toEqual(before);
  });

  it('parses priority input with empty-to-undefined semantics', () => {
    expect(parseRulePriority('')).toBeUndefined();
    expect(parseRulePriority('   ')).toBeUndefined();
    expect(parseRulePriority('42')).toBe(42);
  });
});
