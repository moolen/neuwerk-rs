import type { PolicyCreateRequest, PolicyRuleMatch } from '../../../types';
import type { UpdateDraft } from './formTypes';

export function mutateRuleMatch(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  mutator: (match: PolicyRuleMatch) => void
): void {
  updateDraft((next: PolicyCreateRequest) => {
    const match = next.policy.source_groups[groupIndex]?.rules[ruleIndex]?.match;
    if (!match) {
      return;
    }
    mutator(match);
  });
}
