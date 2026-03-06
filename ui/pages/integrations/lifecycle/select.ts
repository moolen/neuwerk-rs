import { integrationErrorMessage } from '../lifecycleHelpers';
import { loadIntegrationRemote } from '../remote';
import { toIntegrationForm } from '../types';
import type { IntegrationsPageLifecycleDeps } from '../useIntegrationsPageTypes';

export function createSelectIntegrationAction(deps: IntegrationsPageLifecycleDeps) {
  return async (name: string) => {
    try {
      deps.setEditorError(null);
      const view = await loadIntegrationRemote(name);
      deps.setSelectedName(view.name);
      deps.setEditorMode('edit');
      deps.setForm(toIntegrationForm(view));
    } catch (err) {
      deps.setEditorError(integrationErrorMessage(err, 'Failed to load integration'));
    }
  };
}
