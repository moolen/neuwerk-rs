import { describe, expect, it } from 'vitest';

import { addEmptyEntry, displayKey, removeEntry, renameEntryKey, setEntryValue } from './state';

describe('renameEntryKey', () => {
  it('renames existing key and preserves value', () => {
    const next = renameEntryKey(
      { alpha: '1', beta: '2' },
      'alpha',
      'gamma',
      () => '__tmp_fixed'
    );
    expect(next).toEqual({ beta: '2', gamma: '1' });
  });

  it('uses generated temp key when renamed key is blank', () => {
    const next = renameEntryKey(
      { alpha: '1' },
      'alpha',
      '  ',
      () => '__tmp_fixed'
    );
    expect(next).toEqual({ __tmp_fixed: '1' });
  });
});

describe('entry mutation helpers', () => {
  it('setEntryValue updates a key', () => {
    expect(setEntryValue({ alpha: '1' }, 'alpha', '2')).toEqual({ alpha: '2' });
  });

  it('addEmptyEntry appends a generated key', () => {
    expect(addEmptyEntry({ alpha: '1' }, () => '__tmp_fixed')).toEqual({
      alpha: '1',
      __tmp_fixed: '',
    });
  });

  it('removeEntry deletes the targeted key', () => {
    expect(removeEntry({ alpha: '1', beta: '2' }, 'alpha')).toEqual({ beta: '2' });
  });
});

describe('displayKey', () => {
  it('hides temporary keys and keeps regular keys', () => {
    expect(displayKey('__tmp_abc')).toBe('');
    expect(displayKey('x-header')).toBe('x-header');
  });
});
