import type { PolicyCreateRequest } from '../types';
import { validateRuleBasics, validateRuleMatchCore } from './policyValidation/ruleMatchValidation';
import { validateSourceGroup } from './policyValidation/sourceGroupValidation';
import { validateRuleTlsMatch } from './policyValidation/tlsMatchValidation';

export interface PolicyValidationIssue {
  path: string;
  message: string;
}

export function validatePolicyRequest(
  request: PolicyCreateRequest,
  options?: { integrationNames?: Set<string> }
): PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  const integrationNames = options?.integrationNames ?? new Set<string>();

  if (!request.mode || !['disabled', 'audit', 'enforce'].includes(request.mode)) {
    issues.push({ path: 'mode', message: 'Mode must be disabled, audit, or enforce' });
  }

  const groups = request.policy.source_groups ?? [];
  for (let gi = 0; gi < groups.length; gi += 1) {
    const group = groups[gi];
    const groupPath = `policy.source_groups[${gi}]`;

    validateSourceGroup(group, groupPath, integrationNames, issues);

    const rules = group.rules ?? [];
    for (let ri = 0; ri < rules.length; ri += 1) {
      const rule = rules[ri];
      const rulePath = `${groupPath}.rules[${ri}]`;
      validateRuleBasics(rule, rulePath, issues);

      const match = rule.match;
      const proto = validateRuleMatchCore(match, rulePath, issues);

      if (!match.tls) continue;
      const tlsPath = `${rulePath}.match.tls`;
      validateRuleTlsMatch(match.tls, tlsPath, proto, issues);
    }
  }

  return issues;
}
