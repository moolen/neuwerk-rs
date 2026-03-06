import { describe, expect, it } from 'vitest';

import { entryFieldError, entryFieldErrorPath } from './fieldErrors';

describe('fieldErrors', () => {
  it('builds deterministic error paths', () => {
    expect(entryFieldErrorPath('group.0.rule.1.headers', 2, 'key')).toBe(
      'group.0.rule.1.headers.2.key'
    );
    expect(entryFieldErrorPath('group.0.rule.1.headers', 2, 'value')).toBe(
      'group.0.rule.1.headers.2.value'
    );
  });

  it('reads field error values', () => {
    const errors = {
      'group.0.rule.1.headers.2.key': 'bad key',
      'group.0.rule.1.headers.2.value': 'bad value',
    };
    expect(
      entryFieldError(errors, 'group.0.rule.1.headers', 2, 'key')
    ).toBe('bad key');
    expect(
      entryFieldError(errors, 'group.0.rule.1.headers', 2, 'value')
    ).toBe('bad value');
    expect(
      entryFieldError(errors, 'group.0.rule.1.headers', 3, 'value')
    ).toBeUndefined();
  });
});
