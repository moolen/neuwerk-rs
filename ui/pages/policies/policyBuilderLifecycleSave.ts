import { validatePolicyRequest } from '../../utils/policyValidation';
import { savePolicyRemote } from './policyBuilderRemote';
import { errorMessage } from './policyBuilderLifecycleHelpers';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';

type LoadAll = () => Promise<void>;

export function buildHandleSave(
  deps: PolicyBuilderLifecycleDeps,
  loadAll: LoadAll,
): () => Promise<void> {
  const {
    draft,
    integrationNames,
    editorMode,
    editorTargetId,
    setEditorError,
    setSaving,
    setDraft,
    setEditorMode,
    setEditorTargetId,
    setSelectedId,
  } = deps;

  return async () => {
    setEditorError(null);
    const issues = validatePolicyRequest(draft, { integrationNames });
    if (issues.length) {
      setEditorError(`Validation failed (${issues.length} issues). Review the list below.`);
      return;
    }

    setSaving(true);
    try {
      const saved = await savePolicyRemote(editorMode, editorTargetId, draft);
      setDraft(saved.draft);
      setEditorMode(saved.editorMode);
      setEditorTargetId(saved.editorTargetId);
      if (saved.selectedId) {
        setSelectedId(saved.selectedId);
      }
      await loadAll();
    } catch (err) {
      setEditorError(errorMessage(err, 'Failed to save policy'));
    } finally {
      setSaving(false);
    }
  };
}
