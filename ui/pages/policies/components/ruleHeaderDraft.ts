import type { PolicyCreateRequest, PolicyRule } from '../../../types';
import type { UpdateDraft } from './formTypes';

export function mutateRuleHeader(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  mutator: (rule: PolicyRule) => void,
): void {
  updateDraft((next: PolicyCreateRequest) => {
    const rule = next.policy.source_groups[groupIndex]?.rules[ruleIndex];
    if (!rule) {
      return;
    }
    mutator(rule);
  });
}

export function parseRulePriority(value: string): number | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return Number(trimmed);
}
