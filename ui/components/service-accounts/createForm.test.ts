import { describe, expect, it } from 'vitest';

import { buildCreateServiceAccountRequest } from './createForm';

describe('buildCreateServiceAccountRequest', () => {
  it('rejects empty names', () => {
    expect(buildCreateServiceAccountRequest('   ', 'anything')).toEqual({ error: 'Name is required' });
  });

  it('trims values and omits empty description', () => {
    expect(buildCreateServiceAccountRequest('  ci  ', '   ')).toEqual({
      request: { name: 'ci', description: undefined },
    });
  });

  it('returns description when provided', () => {
    expect(buildCreateServiceAccountRequest('ci', ' pipeline ')).toEqual({
      request: { name: 'ci', description: 'pipeline' },
    });
  });
});
