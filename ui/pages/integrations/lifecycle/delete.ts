import { integrationErrorMessage } from '../lifecycleHelpers';
import { deleteIntegrationRemote } from '../remote';
import type { IntegrationsPageLifecycleDeps } from '../useIntegrationsPageTypes';

interface DeleteIntegrationsFollowUps {
  loadIntegrations: () => Promise<void>;
}

export function createDeleteIntegrationAction(
  deps: IntegrationsPageLifecycleDeps,
  followUps: DeleteIntegrationsFollowUps,
  confirmDelete: (message: string) => boolean = window.confirm,
) {
  return async () => {
    if (!deps.selectedName) return;
    const confirmed = confirmDelete(`Delete integration "${deps.selectedName}"?`);
    if (!confirmed) return;
    try {
      await deleteIntegrationRemote(deps.selectedName);
      await followUps.loadIntegrations();
    } catch (err) {
      deps.setEditorError(integrationErrorMessage(err, 'Failed to delete integration'));
    }
  };
}
