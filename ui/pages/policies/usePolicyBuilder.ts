import { useEffect } from 'react';
import { createPolicyBuilderDraftActions } from './policyBuilderDraftActions';
import { createPolicyBuilderLifecycleHandlers } from './policyBuilderLifecycle';
import {
  buildCloseSourceGroupEditor,
  buildOpenSourceGroupEditor,
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
    loadEditorForPolicy,
    loadAll,
    handleSave,
  } = createPolicyBuilderLifecycleHandlers({
    selectedPolicyId,
    editorMode,
    editorTargetId,
    overlayMode,
    overlaySourceGroupId,
    draft,
    integrationNames,
    setPolicies,
    setIntegrations,
    setSelectedPolicyId,
    setOverlayMode,
    setOverlaySourceGroupId,
    setLoading,
    setError,
    setDraft,
    setEditorMode,
    setEditorTargetId,
    setSaving,
    setEditorError,
  });

  const openSourceGroupEditor = buildOpenSourceGroupEditor({
    setOverlayMode,
    setOverlaySourceGroupId,
  });
  const closeSourceGroupEditor = buildCloseSourceGroupEditor({
    setOverlayMode,
    setOverlaySourceGroupId,
  });
  const loadEditorForPolicyWithOverlay = async (policyId: string) => {
    closeSourceGroupEditor();
    await loadEditorForPolicy(policyId);
  };

  useEffect(() => {
    void loadAll();
  }, []);

  useEffect(() => {
    if (!selectedPolicyId || editorTargetId === selectedPolicyId) {
      return;
    }

    void loadEditorForPolicyWithOverlay(selectedPolicyId);
  }, [selectedPolicyId, editorTargetId]);

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
      openSourceGroupEditor,
      closeSourceGroupEditor,
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
