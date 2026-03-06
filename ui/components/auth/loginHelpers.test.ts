import { describe, expect, it } from 'vitest';

import {
  clearLocalPreviewAuthUser,
  createLocalPreviewAuthUser,
  isLocalPreviewAuthBypassEnabled,
  readLocalPreviewAuthUser,
  toLoginErrorMessage,
  validateLoginTokenInput,
  writeLocalPreviewAuthUser,
} from './loginHelpers';

describe('validateLoginTokenInput', () => {
  it('rejects empty values', () => {
    expect(validateLoginTokenInput('   ')).toEqual({ error: 'Token is required' });
  });

  it('returns trimmed token', () => {
    expect(validateLoginTokenInput('  abc  ')).toEqual({ token: 'abc' });
  });

  it('strips bearer prefix', () => {
    expect(validateLoginTokenInput('  Bearer abc.def.ghi  ')).toEqual({
      token: 'abc.def.ghi',
    });
  });
});

describe('toLoginErrorMessage', () => {
  it('uses error message for Error values', () => {
    expect(toLoginErrorMessage(new Error('boom'))).toBe('boom');
  });

  it('uses fallback for unknown values', () => {
    expect(toLoginErrorMessage('bad')).toBe('Invalid token. Please check and try again.');
  });
});

describe('local preview auth helpers', () => {
  it('enables bypass only for localhost hosts', () => {
    expect(isLocalPreviewAuthBypassEnabled('localhost')).toBe(true);
    expect(isLocalPreviewAuthBypassEnabled('127.0.0.1')).toBe(true);
    expect(isLocalPreviewAuthBypassEnabled('::1')).toBe(true);
    expect(isLocalPreviewAuthBypassEnabled('example.com')).toBe(false);
  });

  it('reads and writes preview auth user in local mode', () => {
    const store = new Map<string, string>();
    const storage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => {
        store.set(key, value);
      },
      removeItem: (key: string) => {
        store.delete(key);
      },
    };

    const user = createLocalPreviewAuthUser();
    writeLocalPreviewAuthUser(user, storage, 'localhost');

    expect(readLocalPreviewAuthUser(storage, 'localhost')).toEqual({
      ...user,
      sa_id: null,
      exp: null,
    });

    clearLocalPreviewAuthUser(storage, 'localhost');
    expect(readLocalPreviewAuthUser(storage, 'localhost')).toBeNull();
  });

  it('ignores persisted preview user when host is not local', () => {
    const storage = {
      getItem: () => JSON.stringify(createLocalPreviewAuthUser()),
      removeItem: () => undefined,
      setItem: () => undefined,
    };
    expect(readLocalPreviewAuthUser(storage, 'example.com')).toBeNull();
  });
});
