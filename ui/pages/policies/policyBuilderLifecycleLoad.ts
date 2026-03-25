import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { loadPolicyBuilderRemote, loadPolicyDraftRemote } from './policyBuilderRemote';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type HandleCreate = () => void;
type LoadEditorForPolicy = (policyId: string) => Promise<void>;
type OverlayDeps = Pick<PolicyBuilderLifecycleDeps, 'setOverlayMode' | 'setOverlaySourceGroupId'>;
type SelectPolicyDeps = OverlayDeps & Pick<PolicyBuilderLifecycleDeps, 'setSelectedPolicyId'>;

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
  const { setEditorMode, setEditorTargetId, setSelectedPolicyId, setSelectedId, setDraft, setEditorError } = deps;
  const closeSourceGroupEditor = buildCloseSourceGroupEditor(deps);
  return () => {
    setEditorMode('create');
    setEditorTargetId(null);
    setSelectedPolicyId(null);
    setSelectedId(null);
    setDraft(createEmptyPolicyRequest());
    setEditorError(null);
    closeSourceGroupEditor();
  };
}

export function buildLoadEditorForPolicy(deps: PolicyBuilderLifecycleDeps): LoadEditorForPolicy {
  const {
    setEditorError,
    setSelectedPolicyId,
    setSelectedId,
    setEditorMode,
    setEditorTargetId,
    setDraft,
  } = deps;
  const closeSourceGroupEditor = buildCloseSourceGroupEditor(deps);
  return async (policyId: string) => {
    try {
      setEditorError(null);
      setSelectedPolicyId(policyId);
      setSelectedId(policyId);
      setEditorMode('edit');
      setEditorTargetId(policyId);
      setDraft(await loadPolicyDraftRemote(policyId));
      closeSourceGroupEditor();
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
  const { selectedPolicyId, setSelectedPolicyId, setSelectedId, setLoading, setError, setPolicies, setIntegrations } = deps;
  const closeSourceGroupEditor = buildCloseSourceGroupEditor(deps);
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
        setSelectedId(followUp.policyId);
        closeSourceGroupEditor();
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
