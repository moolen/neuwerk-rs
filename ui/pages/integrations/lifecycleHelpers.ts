import type { IntegrationView } from '../../types';

export type IntegrationsLoadFollowUp =
  | { kind: 'select-first'; name: string }
  | { kind: 'create' }
  | { kind: 'none' };

export function deriveIntegrationsLoadFollowUp(
  integrations: IntegrationView[],
  selectedName: string | null,
): IntegrationsLoadFollowUp {
  if (selectedName) {
    const stillExists = integrations.some((item) => item.name === selectedName);
    if (stillExists) {
      return { kind: 'none' };
    }
  }
  if (integrations.length > 0) {
    return { kind: 'select-first', name: integrations[0].name };
  }
  return { kind: 'create' };
}

export function integrationErrorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}
