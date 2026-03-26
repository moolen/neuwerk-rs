import type { IntegrationView, PolicyCreateRequest, PolicyRecord } from '../../types';
import {
  createPolicy,
  deletePolicy,
  getPolicy,
  listIntegrations,
  listPolicies,
  updatePolicy,
} from '../../services/api';
import { normalizePolicyRequest, sanitizePolicyRequestForApi } from '../../utils/policyModel';

export function sortPoliciesByCreatedAt(items: PolicyRecord[]): PolicyRecord[] {
  return [...items].sort((a, b) => b.created_at.localeCompare(a.created_at));
}

export function filterKubernetesIntegrations(items: IntegrationView[]): IntegrationView[] {
  return items.filter((entry) => entry.kind === 'kubernetes');
}

export async function loadPolicyBuilderRemote(): Promise<{
  policies: PolicyRecord[];
  integrations: IntegrationView[];
}> {
  const [policies, integrations] = await Promise.all([listPolicies(), listIntegrations()]);
  return {
    policies: sortPoliciesByCreatedAt(policies),
    integrations: filterKubernetesIntegrations(integrations),
  };
}

export async function loadPolicyDraftRemote(policyId: string): Promise<PolicyCreateRequest> {
  const record = await getPolicy(policyId);
  return normalizePolicyRequest({ name: record.name, mode: record.mode, policy: record.policy });
}

export async function savePolicyRemote(
  editorMode: 'create' | 'edit',
  editorTargetId: string | null,
  draft: PolicyCreateRequest
): Promise<{
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  selectedPolicyId: string | null;
  draft: PolicyCreateRequest;
}> {
  const request = sanitizePolicyRequestForApi(draft);
  if (editorMode === 'create') {
    const created = await createPolicy(request);
    return {
      editorMode: 'edit',
      editorTargetId: created.id,
      selectedPolicyId: created.id,
      draft: normalizePolicyRequest({ name: created.name, mode: created.mode, policy: created.policy }),
    };
  }

  if (editorTargetId) {
    const updated = await updatePolicy(editorTargetId, request);
    return {
      editorMode: 'edit',
      editorTargetId,
      selectedPolicyId: null,
      draft: normalizePolicyRequest({ name: updated.name, mode: updated.mode, policy: updated.policy }),
    };
  }

  return {
    editorMode,
    editorTargetId,
    selectedPolicyId: null,
    draft,
  };
}

export async function deletePolicyRemote(policyId: string): Promise<void> {
  await deletePolicy(policyId);
}
