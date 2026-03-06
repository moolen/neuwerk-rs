import { useEffect } from 'react';
import type { IntegrationForm } from './types';
import { createIntegrationsLifecycleHandlers } from './useIntegrationsPageLifecycle';
import { useIntegrationsPageState } from './useIntegrationsPageState';
import type { UseIntegrationsPageActions, UseIntegrationsPageState } from './useIntegrationsPageTypes';

export function useIntegrationsPage(): UseIntegrationsPageState & UseIntegrationsPageActions {
  const {
    integrations,
    setIntegrations,
    selectedName,
    setSelectedName,
    editorMode,
    setEditorMode,
    form,
    setForm,
    loading,
    setLoading,
    saving,
    setSaving,
    error,
    setError,
    editorError,
    setEditorError,
  } = useIntegrationsPageState();

  useEffect(() => {
    void loadIntegrations();
  }, []);

  const {
    createNewIntegration,
    selectIntegration,
    loadIntegrations,
    saveIntegration,
    deleteSelectedIntegration,
  } = createIntegrationsLifecycleHandlers({
    selectedName,
    editorMode,
    form,
    setIntegrations,
    setSelectedName,
    setEditorMode,
    setForm,
    setLoading,
    setSaving,
    setError,
    setEditorError,
  });

  const setFormField = (field: keyof IntegrationForm, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  return {
    integrations,
    selectedName,
    editorMode,
    form,
    loading,
    saving,
    error,
    editorError,
    loadIntegrations,
    selectIntegration,
    createNewIntegration,
    saveIntegration,
    deleteSelectedIntegration,
    setFormField,
  };
}
