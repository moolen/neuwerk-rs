import { runCreateNewIntegration } from './lifecycle/createNew';
import { createDeleteIntegrationAction } from './lifecycle/delete';
import { createLoadIntegrationsAction } from './lifecycle/load';
import { createSaveIntegrationAction } from './lifecycle/save';
import { createSelectIntegrationAction } from './lifecycle/select';
import type { IntegrationsPageLifecycleDeps } from './useIntegrationsPageTypes';

export function createIntegrationsLifecycleHandlers(deps: IntegrationsPageLifecycleDeps): {
  createNewIntegration: () => void;
  selectIntegration: (name: string) => Promise<void>;
  loadIntegrations: () => Promise<void>;
  saveIntegration: () => Promise<void>;
  deleteSelectedIntegration: () => Promise<void>;
} {
  const {
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
  } = deps;

  const lifecycleDeps: IntegrationsPageLifecycleDeps = {
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
  };

  const createNewIntegration = () => runCreateNewIntegration(lifecycleDeps);

  const selectIntegration = createSelectIntegrationAction(lifecycleDeps);

  const loadIntegrations = createLoadIntegrationsAction(lifecycleDeps, {
    selectIntegration,
    createNewIntegration,
  });

  const saveIntegration = createSaveIntegrationAction(lifecycleDeps, {
    loadIntegrations,
    selectIntegration,
  });

  const deleteSelectedIntegration = createDeleteIntegrationAction(lifecycleDeps, {
    loadIntegrations,
  });

  return {
    createNewIntegration,
    selectIntegration,
    loadIntegrations,
    saveIntegration,
    deleteSelectedIntegration,
  };
}
