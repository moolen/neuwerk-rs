import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { deletePolicyRemote } from './policyBuilderRemote';
import { errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type HandleCreate = () => void;
type LoadAll = () => Promise<void>;

export function buildHandleDelete(
  deps: PolicyBuilderLifecycleDeps,
  loadAll: LoadAll,
  _handleCreate: HandleCreate,
): (policyId: string) => Promise<void> {
  const {
    editorTargetId,
    setDraft,
    setEditorError,
    setEditorMode,
    setEditorTargetId,
    setError,
  } = deps;
  return async (policyId: string) => {
    const confirmed = window.confirm('Delete this policy?');
    if (!confirmed) return;
    try {
      await deletePolicyRemote(policyId);
      await loadAll();
      if (editorTargetId === policyId) {
        setDraft(createEmptyPolicyRequest());
        setEditorError(null);
        setEditorMode('create');
        setEditorTargetId(null);
      }
    } catch (err) {
      setError(errorMessage(err, 'Failed to delete policy'));
    }
  };
}
