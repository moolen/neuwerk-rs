import { describe, expect, it } from 'vitest';

import {
  buildCreateServiceAccountRequest,
  buildUpdateServiceAccountRequest,
} from './createForm';

describe('buildCreateServiceAccountRequest', () => {
  it('rejects empty names', () => {
    expect(buildCreateServiceAccountRequest('   ', 'anything', 'readonly')).toEqual({
      error: 'Name is required',
    });
  });

  it('trims values and omits empty description', () => {
    expect(buildCreateServiceAccountRequest('  ci  ', '   ', 'readonly')).toEqual({
      request: { name: 'ci', description: undefined, role: 'readonly' },
    });
  });

  it('returns description when provided', () => {
    expect(buildCreateServiceAccountRequest('ci', ' pipeline ', 'admin')).toEqual({
      request: { name: 'ci', description: 'pipeline', role: 'admin' },
    });
  });
});

describe('buildUpdateServiceAccountRequest', () => {
  it('rejects empty names', () => {
    expect(buildUpdateServiceAccountRequest('   ', 'anything', 'readonly')).toEqual({
      error: 'Name is required',
    });
  });

  it('keeps role and trimmed values', () => {
    expect(buildUpdateServiceAccountRequest('  ci  ', ' pipeline ', 'readonly')).toEqual({
      request: { name: 'ci', description: 'pipeline', role: 'readonly' },
    });
  });
});
