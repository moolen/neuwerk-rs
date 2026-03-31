import type { PolicyCreateRequest, PolicyRule, PolicySourceGroup } from '../../types';
import {
  createEmptyRule,
  createEmptySourceGroup,
  createSourceGroupClientKey,
  createRuleTemplate,
  nextNamedId,
} from '../../utils/policyModel';
import type { RuleTemplateId } from './helpers';
import { duplicateId, moveItem } from './helpers';

function cloneGroup(group: PolicySourceGroup): PolicySourceGroup {
  return JSON.parse(JSON.stringify(group)) as PolicySourceGroup;
}

function cloneRule(rule: PolicyRule): PolicyRule {
  return JSON.parse(JSON.stringify(rule)) as PolicyRule;
}

export function addGroupToDraft(draft: PolicyCreateRequest): void {
  const id = nextNamedId('group', draft.policy.source_groups.map((group) => group.id));
  const group = createEmptySourceGroup(id);
  group.priority = draft.policy.source_groups.length;
  draft.policy.source_groups.push(group);
}

export function duplicateGroupInDraft(draft: PolicyCreateRequest, groupIndex: number): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) {
    return;
  }
  const existingIds = draft.policy.source_groups.map((entry) => entry.id);
  const copy = cloneGroup(group);
  copy.client_key = createSourceGroupClientKey(copy.id);
  copy.id = duplicateId(copy.id, existingIds);
  draft.policy.source_groups.splice(groupIndex + 1, 0, copy);
}

export function moveGroupInDraft(
  draft: PolicyCreateRequest,
  groupIndex: number,
  direction: -1 | 1
): void {
  draft.policy.source_groups = moveItem(draft.policy.source_groups, groupIndex, direction);
}

export function deleteGroupInDraft(draft: PolicyCreateRequest, groupIndex: number): void {
  draft.policy.source_groups.splice(groupIndex, 1);
}

export function addRuleToGroupInDraft(draft: PolicyCreateRequest, groupIndex: number): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) {
    return;
  }
  const id = nextNamedId('rule', group.rules.map((rule) => rule.id));
  group.rules.push(createEmptyRule(id));
}

export function addTemplateRuleToGroupInDraft(
  draft: PolicyCreateRequest,
  groupIndex: number,
  template: RuleTemplateId
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) {
    return;
  }
  const id = nextNamedId('rule', group.rules.map((rule) => rule.id));
  group.rules.push(createRuleTemplate(template, id));
}

export function duplicateRuleInGroupInDraft(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number
): void {
  const group = draft.policy.source_groups[groupIndex];
  const rule = group?.rules[ruleIndex];
  if (!group || !rule) {
    return;
  }
  const copy = cloneRule(rule);
  copy.id = duplicateId(copy.id, group.rules.map((entry) => entry.id));
  group.rules.splice(ruleIndex + 1, 0, copy);
}

export function moveRuleInGroupInDraft(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
  direction: -1 | 1
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) {
    return;
  }
  group.rules = moveItem(group.rules, ruleIndex, direction);
}

export function deleteRuleInGroupInDraft(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) {
    return;
  }
  group.rules.splice(ruleIndex, 1);
}
