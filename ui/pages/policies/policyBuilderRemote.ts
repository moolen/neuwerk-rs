import type { IntegrationView, PolicyCreateRequest } from '../../types';
import {
  getPolicy,
  listIntegrations,
  updatePolicy,
} from '../../services/api';
import {
  normalizePolicyRequest,
  sanitizePolicyRequestForApi,
} from '../../utils/policyModel';

export const SINGLETON_POLICY_ID = 'singleton';

export function filterKubernetesIntegrations(items: IntegrationView[]): IntegrationView[] {
  return items.filter((entry) => entry.kind === 'kubernetes');
}

export async function loadPolicyBuilderRemote(): Promise<{
  draft: PolicyCreateRequest;
  integrations: IntegrationView[];
}> {
  const [policy, integrations] = await Promise.all([getPolicy(), listIntegrations()]);
  return {
    draft: normalizePolicyRequest(policy),
    integrations: filterKubernetesIntegrations(integrations),
  };
}

export async function loadPolicyDraftRemote(_policyId: string): Promise<PolicyCreateRequest> {
  return normalizePolicyRequest(await getPolicy());
}

export async function savePolicyRemote(
  _editorMode: 'create' | 'edit',
  _editorTargetId: string | null,
  draft: PolicyCreateRequest
): Promise<{
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  selectedPolicyId: string | null;
  draft: PolicyCreateRequest;
}> {
  const updated = await updatePolicy(sanitizePolicyRequestForApi(draft).policy);

  return {
    editorMode: 'edit',
    editorTargetId: SINGLETON_POLICY_ID,
    selectedPolicyId: SINGLETON_POLICY_ID,
    draft: normalizePolicyRequest(updated),
  };
}
