import { validateIntegrationFormForSave } from '../formValidation';
import { integrationErrorMessage } from '../lifecycleHelpers';
import { saveIntegrationRemote } from '../remote';
import type { EditorMode } from '../types';
import type { IntegrationsPageLifecycleDeps } from '../useIntegrationsPageTypes';

interface SaveIntegrationsFollowUps {
  loadIntegrations: () => Promise<void>;
  selectIntegration: (name: string) => Promise<void>;
}

export function nextSelectionAfterSave(
  editorMode: EditorMode,
  createdName: string | null,
): string | null {
  if (editorMode !== 'create') return null;
  return createdName ?? null;
}

export function createSaveIntegrationAction(
  deps: IntegrationsPageLifecycleDeps,
  followUps: SaveIntegrationsFollowUps,
) {
  return async () => {
    const validation = validateIntegrationFormForSave(deps.form, deps.editorMode);
    if (!validation.value) {
      deps.setEditorError(validation.error ?? 'Invalid integration form');
      return;
    }

    try {
      deps.setSaving(true);
      deps.setEditorError(null);
      const createdName = await saveIntegrationRemote(
        deps.editorMode,
        deps.selectedName,
        validation.value,
        deps.form,
      );
      await followUps.loadIntegrations();
      const nextSelection = nextSelectionAfterSave(deps.editorMode, createdName);
      if (nextSelection) {
        await followUps.selectIntegration(nextSelection);
      }
    } catch (err) {
      deps.setEditorError(integrationErrorMessage(err, 'Failed to save integration'));
    } finally {
      deps.setSaving(false);
    }
  };
}
