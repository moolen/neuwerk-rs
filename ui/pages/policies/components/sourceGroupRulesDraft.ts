import type { RuleTemplateId } from '../helpers';

export function selectedRuleTemplate(
  templateByGroup: Record<number, RuleTemplateId>,
  groupIndex: number
): RuleTemplateId {
  return templateByGroup[groupIndex] ?? 'l4_allow';
}

export function withGroupTemplate(
  prev: Record<number, RuleTemplateId>,
  groupIndex: number,
  template: RuleTemplateId
): Record<number, RuleTemplateId> {
  return {
    ...prev,
    [groupIndex]: template,
  };
}
