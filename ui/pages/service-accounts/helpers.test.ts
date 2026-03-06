import { describe, expect, it } from 'vitest';

import { toUiError } from './helpers';

describe('toUiError', () => {
  it('returns error message for Error instances', () => {
    expect(toUiError(new Error('boom'), 'fallback')).toBe('boom');
  });

  it('returns fallback for unknown values', () => {
    expect(toUiError('oops', 'fallback')).toBe('fallback');
  });
});
