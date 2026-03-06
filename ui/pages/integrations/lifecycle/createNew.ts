import { createEmptyIntegrationForm } from '../types';
import type { IntegrationsPageLifecycleDeps } from '../useIntegrationsPageTypes';

export function runCreateNewIntegration(deps: IntegrationsPageLifecycleDeps) {
  deps.setEditorMode('create');
  deps.setSelectedName(null);
  deps.setForm(createEmptyIntegrationForm());
  deps.setEditorError(null);
}
