import { describe, expect, it } from 'vitest';

import { isPolicySaveDisabled, policyEditorSubtitle } from './policiesPageHelpers';

describe('policiesPageHelpers', () => {
  it('formats editor subtitle for create/edit modes', () => {
    expect(policyEditorSubtitle('create', null)).toBe('Creating a new policy');
    expect(policyEditorSubtitle('edit', '1234567890abcdef')).toBe('Editing 12345678');
    expect(policyEditorSubtitle('edit', null)).toBe('Editing policy');
  });

  it('derives save disabled state from saving/validation flags', () => {
    expect(isPolicySaveDisabled(false, 0)).toBe(false);
    expect(isPolicySaveDisabled(true, 0)).toBe(true);
    expect(isPolicySaveDisabled(false, 1)).toBe(true);
  });
});
