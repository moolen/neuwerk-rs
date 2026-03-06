import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { loadPolicyBuilderRemote, loadPolicyDraftRemote } from './policyBuilderRemote';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type HandleCreate = () => void;
type LoadEditorForPolicy = (policyId: string) => Promise<void>;

export function buildHandleCreate(deps: PolicyBuilderLifecycleDeps): HandleCreate {
  const { setEditorMode, setEditorTargetId, setSelectedId, setDraft, setEditorError } = deps;
  return () => {
    setEditorMode('create');
    setEditorTargetId(null);
    setSelectedId(null);
    setDraft(createEmptyPolicyRequest());
    setEditorError(null);
  };
}

export function buildLoadEditorForPolicy(deps: PolicyBuilderLifecycleDeps): LoadEditorForPolicy {
  const { setEditorError, setSelectedId, setEditorMode, setEditorTargetId, setDraft } = deps;
  return async (policyId: string) => {
    try {
      setEditorError(null);
      setSelectedId(policyId);
      setEditorMode('edit');
      setEditorTargetId(policyId);
      setDraft(await loadPolicyDraftRemote(policyId));
    } catch (err) {
      setEditorError(errorMessage(err, 'Failed to load policy'));
    }
  };
}

export function buildLoadAll(
  deps: PolicyBuilderLifecycleDeps,
  loadEditorForPolicy: LoadEditorForPolicy,
  handleCreate: HandleCreate,
): () => Promise<void> {
  const { selectedId, setLoading, setError, setPolicies, setIntegrations } = deps;
  return async () => {
    try {
      setLoading(true);
      setError(null);
      const { policies, integrations } = await loadPolicyBuilderRemote();
      setPolicies(policies);
      setIntegrations(integrations);

      const followUp = deriveLoadAllFollowUp(policies, selectedId);
      if (followUp.kind === 'open-first') {
        await loadEditorForPolicy(followUp.policyId);
      } else if (followUp.kind === 'create') {
        handleCreate();
      }
    } catch (err) {
      setError(errorMessage(err, 'Failed to load policies'));
    } finally {
      setLoading(false);
    }
  };
}
