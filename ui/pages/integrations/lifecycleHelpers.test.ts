import { describe, expect, it } from 'vitest';

import type { IntegrationView } from '../../types';
import { deriveIntegrationsLoadFollowUp, integrationErrorMessage } from './lifecycleHelpers';

describe('integrations lifecycle helpers', () => {
  it('derives load follow-up based on current selection and list contents', () => {
    const integrations = [{ name: 'a' }, { name: 'b' }] as IntegrationView[];
    expect(deriveIntegrationsLoadFollowUp(integrations, 'a')).toEqual({ kind: 'none' });
    expect(deriveIntegrationsLoadFollowUp(integrations, 'missing')).toEqual({
      kind: 'select-first',
      name: 'a',
    });
    expect(deriveIntegrationsLoadFollowUp([], null)).toEqual({ kind: 'create' });
  });

  it('maps unknown errors to fallback messages', () => {
    expect(integrationErrorMessage(new Error('boom'), 'fallback')).toBe('boom');
    expect(integrationErrorMessage(null, 'fallback')).toBe('fallback');
  });
});
