import type { PolicyRule } from '../../../types';
import type { ValidationIssueLike } from './types';

export function validateRuleBasics(rule: PolicyRule, rulePath: string, issues: ValidationIssueLike[]) {
  if (!rule.id.trim()) {
    issues.push({ path: `${rulePath}.id`, message: 'Rule id is required' });
  }
  if (typeof rule.priority === 'number' && rule.priority < 0) {
    issues.push({ path: `${rulePath}.priority`, message: 'Priority must be >= 0' });
  }
  if (!['allow', 'deny'].includes(rule.action)) {
    issues.push({ path: `${rulePath}.action`, message: 'Rule action must be allow or deny' });
  }
  if (rule.mode && !['audit', 'enforce'].includes(rule.mode)) {
    issues.push({ path: `${rulePath}.mode`, message: 'Rule mode must be audit or enforce' });
  }
}
