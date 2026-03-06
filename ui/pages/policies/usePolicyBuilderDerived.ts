import { useMemo } from 'react';

import type { IntegrationView, PolicyCreateRequest } from '../../types';
import { validatePolicyRequest } from '../../utils/policyValidation';
import type { PolicyValidationIssue } from '../../utils/policyValidation';

export function collectIntegrationNames(integrations: IntegrationView[]): Set<string> {
  return new Set(integrations.map((integration) => integration.name));
}

export function derivePolicyValidationIssues(
  draft: PolicyCreateRequest,
  integrationNames: Set<string>,
): PolicyValidationIssue[] {
  return validatePolicyRequest(draft, { integrationNames });
}

export function usePolicyBuilderDerived(
  draft: PolicyCreateRequest,
  integrations: IntegrationView[],
): {
  integrationNames: Set<string>;
  validationIssues: PolicyValidationIssue[];
} {
  const integrationNames = useMemo(() => collectIntegrationNames(integrations), [integrations]);
  const validationIssues = useMemo(
    () => derivePolicyValidationIssues(draft, integrationNames),
    [draft, integrationNames],
  );
  return { integrationNames, validationIssues };
}
