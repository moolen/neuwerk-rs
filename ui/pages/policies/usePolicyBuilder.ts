import { useEffect } from 'react';
import { createPolicyBuilderDraftActions } from './policyBuilderDraftActions';
import { createPolicyBuilderLifecycleHandlers } from './policyBuilderLifecycle';
import {
  buildCloseSourceGroupEditor,
  buildOpenSourceGroupEditor,
  buildSelectPolicy,
} from './policyBuilderLifecycleLoad';
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
    selectedPolicyId,
    setSelectedPolicyId,
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
    overlayMode,
    setOverlayMode,
    overlaySourceGroupId,
    setOverlaySourceGroupId,
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
    selectedId: selectedPolicyId,
    editorMode,
    editorTargetId,
    draft,
    integrationNames,
    setPolicies,
    setIntegrations,
    setSelectedId: setSelectedPolicyId,
    setLoading,
    setError,
    setDraft,
    setEditorMode,
    setEditorTargetId,
    setSaving,
    setEditorError,
  });

  const selectPolicy = buildSelectPolicy({
    setSelectedPolicyId,
    setOverlayMode,
    setOverlaySourceGroupId,
  });
  const openSourceGroupEditor = buildOpenSourceGroupEditor({
    setOverlayMode,
    setOverlaySourceGroupId,
  });
  const closeSourceGroupEditor = buildCloseSourceGroupEditor({
    setOverlayMode,
    setOverlaySourceGroupId,
  });
  const handleCreateWithOverlay = () => {
    closeSourceGroupEditor();
    handleCreate();
  };
  const loadEditorForPolicyWithOverlay = async (policyId: string) => {
    closeSourceGroupEditor();
    await loadEditorForPolicy(policyId);
  };

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
      selectedPolicyId,
      selectedId: selectedPolicyId,
      loading,
      error,
      draft,
      editorMode,
      editorTargetId,
      overlayMode,
      overlaySourceGroupId,
      saving,
      editorError,
      validationIssues,
    },
    actions: {
      loadAll,
      loadEditorForPolicy: loadEditorForPolicyWithOverlay,
      selectPolicy,
      openSourceGroupEditor,
      closeSourceGroupEditor,
      handleCreate: handleCreateWithOverlay,
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
