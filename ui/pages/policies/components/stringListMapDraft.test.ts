import { describe, expect, it } from 'vitest';

import {
  addStringListMapRow,
  createStringListMapKey,
  removeStringListMapRow,
  renameStringListMapRow,
  updateStringListMapRow,
} from './stringListMapDraft';

describe('stringListMapDraft', () => {
  it('creates deterministic generated keys', () => {
    expect(createStringListMapKey(42)).toBe('key_42');
  });

  it('adds and removes rows', () => {
    const base = { a: ['1'] };
    const added = addStringListMapRow(base, 99);
    expect(added).toEqual({ a: ['1'], key_99: [] });
    const removed = removeStringListMapRow(added, 'a');
    expect(removed).toEqual({ key_99: [] });
  });

  it('renames keys and falls back to generated key when blank', () => {
    const base = { old: ['v1'], keep: ['v2'] };
    expect(renameStringListMapRow(base, 'old', 'new')).toEqual({
      new: ['v1'],
      keep: ['v2'],
    });
    expect(renameStringListMapRow(base, 'old', '   ', 123)).toEqual({
      key_123: ['v1'],
      keep: ['v2'],
    });
  });

  it('updates list values using comma-separated parsing', () => {
    const base = { header: ['a'] };
    expect(updateStringListMapRow(base, 'header', 'x, y,  ,z')).toEqual({
      header: ['x', 'y', 'z'],
    });
  });
});
