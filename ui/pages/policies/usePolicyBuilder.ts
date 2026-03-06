import { useEffect } from 'react';
import { createPolicyBuilderDraftActions } from './policyBuilderDraftActions';
import { createPolicyBuilderLifecycleHandlers } from './policyBuilderLifecycle';
import { createUpdateDraft } from './usePolicyBuilderDraft';
import { usePolicyBuilderDerived } from './usePolicyBuilderDerived';
import { usePolicyBuilderState } from './usePolicyBuilderState';
import type { UsePolicyBuilderResult } from './usePolicyBuilderTypes';

export function usePolicyBuilder(): UsePolicyBuilderResult {
  const {
    policies,
    setPolicies,
    integrations,
    setIntegrations,
    selectedId,
    setSelectedId,
    loading,
    setLoading,
    error,
    setError,
    draft,
    setDraft,
    editorMode,
    setEditorMode,
    editorTargetId,
    setEditorTargetId,
    saving,
    setSaving,
    editorError,
    setEditorError,
  } = usePolicyBuilderState();

  const { integrationNames, validationIssues } = usePolicyBuilderDerived(draft, integrations);

  const updateDraft = createUpdateDraft(setDraft);

  const {
    handleCreate,
    loadEditorForPolicy,
    loadAll,
    handleDelete,
    handleSave,
  } = createPolicyBuilderLifecycleHandlers({
    selectedId,
    editorMode,
    editorTargetId,
    draft,
    integrationNames,
    setPolicies,
    setIntegrations,
    setSelectedId,
    setLoading,
    setError,
    setDraft,
    setEditorMode,
    setEditorTargetId,
    setSaving,
    setEditorError,
  });

  useEffect(() => {
    void loadAll();
  }, []);

  const {
    addGroup,
    duplicateGroup,
    moveGroup,
    deleteGroup,
    addRule,
    duplicateRule,
    moveRule,
    deleteRule,
  } = createPolicyBuilderDraftActions({ updateDraft });

  return {
    state: {
      policies,
      integrations,
      selectedId,
      loading,
      error,
      draft,
      editorMode,
      editorTargetId,
      saving,
      editorError,
      validationIssues,
    },
    actions: {
      loadAll,
      loadEditorForPolicy,
      handleCreate,
      handleDelete,
      handleSave,
      updateDraft,
      setDraft,
      addGroup,
      duplicateGroup,
      moveGroup,
      deleteGroup,
      addRule,
      duplicateRule,
      moveRule,
      deleteRule,
    },
  };
}
