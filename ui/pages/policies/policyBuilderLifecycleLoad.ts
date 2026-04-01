import {
  loadPolicyBuilderRemote,
  loadPolicyDraftRemote,
  SINGLETON_POLICY_ID,
} from './policyBuilderRemote';
import { errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type LoadEditorForPolicy = (policyId: string) => Promise<void>;
type OverlayDeps = Pick<
  PolicyBuilderLifecycleDeps,
  'setOverlayMode' | 'setOverlaySourceGroupId'
>;

export function buildCloseSourceGroupEditor(deps: OverlayDeps): () => void {
  const { setOverlayMode, setOverlaySourceGroupId } = deps;
  return () => {
    setOverlayMode('closed');
    setOverlaySourceGroupId(null);
  };
}

export function buildOpenSourceGroupEditor(
  deps: OverlayDeps,
): (sourceGroupId: string | null) => void {
  const { setOverlayMode, setOverlaySourceGroupId } = deps;
  return (sourceGroupId: string | null) => {
    setOverlayMode(sourceGroupId ? 'edit-group' : 'create-group');
    setOverlaySourceGroupId(sourceGroupId);
  };
}

export function buildLoadEditorForPolicy(deps: PolicyBuilderLifecycleDeps): LoadEditorForPolicy {
  const {
    setEditorError,
    setSelectedPolicyId,
    setEditorMode,
    setEditorTargetId,
    setDraft,
  } = deps;
  return async (policyId: string) => {
    try {
      setEditorError(null);
      setSelectedPolicyId(policyId);
      setEditorMode('edit');
      setEditorTargetId(policyId);
      setDraft(await loadPolicyDraftRemote(policyId));
    } catch (err) {
      setEditorError(errorMessage(err, 'Failed to load policy'));
    }
  };
}

export function buildLoadAll(deps: PolicyBuilderLifecycleDeps): () => Promise<void> {
  const {
    setLoading,
    setError,
    setPolicies,
    setIntegrations,
    setSelectedPolicyId,
    setDraft,
    setEditorMode,
    setEditorTargetId,
    setEditorError,
  } = deps;
  return async () => {
    try {
      setLoading(true);
      setError(null);
      const { draft, integrations } = await loadPolicyBuilderRemote();
      setDraft(draft);
      setPolicies([
        {
          id: SINGLETON_POLICY_ID,
          created_at: '',
          mode: draft.mode,
          policy: draft.policy,
        },
      ]);
      setIntegrations(integrations);
      setSelectedPolicyId(SINGLETON_POLICY_ID);
      setEditorMode('edit');
      setEditorTargetId(SINGLETON_POLICY_ID);
      setEditorError(null);
    } catch (err) {
      setError(errorMessage(err, 'Failed to load policies'));
    } finally {
      setLoading(false);
    }
  };
}
