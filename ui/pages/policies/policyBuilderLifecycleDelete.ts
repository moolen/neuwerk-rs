import { deletePolicyRemote } from './policyBuilderRemote';
import { errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type HandleCreate = () => void;
type LoadAll = () => Promise<void>;

export function buildHandleDelete(
  deps: PolicyBuilderLifecycleDeps,
  loadAll: LoadAll,
  handleCreate: HandleCreate,
): (policyId: string) => Promise<void> {
  const { selectedId, editorTargetId, setSelectedId, setError } = deps;
  return async (policyId: string) => {
    const confirmed = window.confirm('Delete this policy?');
    if (!confirmed) return;
    try {
      await deletePolicyRemote(policyId);
      await loadAll();
      if (selectedId === policyId) setSelectedId(null);
      if (editorTargetId === policyId) handleCreate();
    } catch (err) {
      setError(errorMessage(err, 'Failed to delete policy'));
    }
  };
}
