import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../types';
import { createEmptyPolicyRequest, createEmptyRule, createEmptySourceGroup } from '../../utils/policyModel';
import {
  addGroupToDraft,
  addRuleToGroupInDraft,
  addTemplateRuleToGroupInDraft,
  deleteGroupInDraft,
  deleteRuleInGroupInDraft,
  duplicateGroupInDraft,
  duplicateRuleInGroupInDraft,
  moveGroupInDraft,
  moveRuleInGroupInDraft,
} from './policyBuilderDraftMutations';

function makeDraft(): PolicyCreateRequest {
  const draft = createEmptyPolicyRequest();
  const g1 = createEmptySourceGroup('group-1');
  g1.rules = [createEmptyRule('rule-1')];
  const g2 = createEmptySourceGroup('group-2');
  g2.rules = [createEmptyRule('rule-2')];
  draft.policy.source_groups = [g1, g2];
  return draft;
}

describe('policyBuilderDraftMutations', () => {
  it('adds and duplicates groups', () => {
    const draft = makeDraft();
    addGroupToDraft(draft);
    expect(draft.policy.source_groups.at(-1)?.id).toBe('group-3');

    duplicateGroupInDraft(draft, 0);
    expect(draft.policy.source_groups[1].id).toBe('group-4');
    expect(draft.policy.source_groups[1].rules[0].id).toBe('rule-1');
  });

  it('moves and deletes groups', () => {
    const draft = makeDraft();
    moveGroupInDraft(draft, 0, 1);
    expect(draft.policy.source_groups.map((group) => group.id)).toEqual(['group-2', 'group-1']);

    deleteGroupInDraft(draft, 1);
    expect(draft.policy.source_groups.map((group) => group.id)).toEqual(['group-2']);
  });

  it('adds blank and template rules', () => {
    const draft = makeDraft();
    addRuleToGroupInDraft(draft, 0);
    expect(draft.policy.source_groups[0].rules.at(-1)?.id).toBe('rule-2');

    addTemplateRuleToGroupInDraft(draft, 0, 'tls_metadata');
    const templateRule = draft.policy.source_groups[0].rules.at(-1);
    expect(templateRule?.match.tls?.mode).toBe('metadata');
  });

  it('duplicates, moves, and deletes rules', () => {
    const draft = makeDraft();
    addRuleToGroupInDraft(draft, 0); // rule-2
    duplicateRuleInGroupInDraft(draft, 0, 0);
    expect(draft.policy.source_groups[0].rules[1].id).toBe('rule-3');

    moveRuleInGroupInDraft(draft, 0, 0, 1);
    expect(draft.policy.source_groups[0].rules[1].id).toBe('rule-1');

    deleteRuleInGroupInDraft(draft, 0, 1);
    expect(draft.policy.source_groups[0].rules.some((rule) => rule.id === 'rule-1')).toBe(false);
  });

  it('no-ops for out-of-range group/rule references', () => {
    const draft = makeDraft();
    expect(() => {
      addRuleToGroupInDraft(draft, 99);
      addTemplateRuleToGroupInDraft(draft, 99, 'l4_allow');
      duplicateRuleInGroupInDraft(draft, 0, 99);
      moveRuleInGroupInDraft(draft, 99, 0, 1);
      deleteRuleInGroupInDraft(draft, 99, 0);
      duplicateGroupInDraft(draft, 99);
    }).not.toThrow();
  });
});
