import { describe, expect, it } from 'vitest';

import { nextSelectionAfterSave } from './save';

describe('integration lifecycle save helpers', () => {
  it('selects newly created integrations after create-mode save', () => {
    expect(nextSelectionAfterSave('create', 'cluster-a')).toBe('cluster-a');
    expect(nextSelectionAfterSave('create', null)).toBeNull();
  });

  it('does not force selection update for edit-mode saves', () => {
    expect(nextSelectionAfterSave('edit', 'cluster-a')).toBeNull();
  });
});
