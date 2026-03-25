import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { loadPolicyBuilderRemote, loadPolicyDraftRemote } from './policyBuilderRemote';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type HandleCreate = () => void;
type LoadEditorForPolicy = (policyId: string) => Promise<void>;
type OverlayDeps = {
  setOverlayMode: (mode: 'closed' | 'create-group' | 'edit-group') => void;
  setOverlaySourceGroupId: (sourceGroupId: string | null) => void;
};
type SelectPolicyDeps = OverlayDeps & { setSelectedPolicyId: (policyId: string | null) => void };

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

export function buildSelectPolicy(deps: SelectPolicyDeps): (policyId: string) => void {
  const { setSelectedPolicyId } = deps;
  const closeSourceGroupEditor = buildCloseSourceGroupEditor(deps);
  return (policyId: string) => {
    setSelectedPolicyId(policyId);
    closeSourceGroupEditor();
  };
}

export function buildHandleCreate(deps: PolicyBuilderLifecycleDeps): HandleCreate {
  const { setEditorMode, setEditorTargetId, setSelectedPolicyId, setDraft, setEditorError } = deps;
  return () => {
    setEditorMode('create');
    setEditorTargetId(null);
    setSelectedPolicyId(null);
    setDraft(createEmptyPolicyRequest());
    setEditorError(null);
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

export function buildLoadAll(
  deps: PolicyBuilderLifecycleDeps,
  _loadEditorForPolicy: LoadEditorForPolicy,
  handleCreate: HandleCreate,
): () => Promise<void> {
  const { selectedPolicyId, setLoading, setError, setPolicies, setIntegrations, setSelectedPolicyId } = deps;
  return async () => {
    try {
      setLoading(true);
      setError(null);
      const { policies, integrations } = await loadPolicyBuilderRemote();
      setPolicies(policies);
      setIntegrations(integrations);

      const followUp = deriveLoadAllFollowUp(policies, selectedPolicyId);
      if (followUp.kind === 'select-first') {
        setSelectedPolicyId(followUp.policyId);
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
