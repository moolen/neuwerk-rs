import { deriveIntegrationsLoadFollowUp, integrationErrorMessage } from '../lifecycleHelpers';
import { loadIntegrationsRemote } from '../remote';
import type { IntegrationsPageLifecycleDeps } from '../useIntegrationsPageTypes';

interface LoadIntegrationsFollowUps {
  selectIntegration: (name: string) => Promise<void>;
  createNewIntegration: () => void;
}

export function createLoadIntegrationsAction(
  deps: IntegrationsPageLifecycleDeps,
  followUps: LoadIntegrationsFollowUps,
) {
  return async () => {
    try {
      deps.setLoading(true);
      deps.setError(null);
      const sorted = await loadIntegrationsRemote();
      deps.setIntegrations(sorted);
      const followUp = deriveIntegrationsLoadFollowUp(sorted, deps.selectedName);
      if (followUp.kind === 'select-first') {
        await followUps.selectIntegration(followUp.name);
      } else if (followUp.kind === 'create') {
        followUps.createNewIntegration();
      }
    } catch (err) {
      deps.setError(integrationErrorMessage(err, 'Failed to load integrations'));
    } finally {
      deps.setLoading(false);
    }
  };
}
