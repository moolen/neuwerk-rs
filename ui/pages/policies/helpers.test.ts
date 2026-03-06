import { describe, expect, it } from 'vitest';

import {
  duplicateId,
  emptyKubernetesSource,
  emptyTlsHeaders,
  emptyTlsNameMatch,
  formatIssues,
  listToText,
  moveItem,
  numberListToText,
  parseProtoKind,
  textToList,
  textToNumberList,
} from './helpers';

describe('policies helpers', () => {
  it('converts text and list values', () => {
    expect(listToText(['a', 'b'])).toBe('a\nb');
    expect(textToList('a,b\n c')).toEqual(['a', 'b', 'c']);
  });

  it('converts numeric lists from text', () => {
    expect(numberListToText([1, 2, 3])).toBe('1, 2, 3');
    expect(textToNumberList('1, 2\n3.9, bad')).toEqual([1, 2, 3]);
  });

  it('parses protocol kinds', () => {
    expect(parseProtoKind()).toEqual({ kind: 'any', custom: '' });
    expect(parseProtoKind(' tcp ')).toEqual({ kind: 'tcp', custom: '' });
    expect(parseProtoKind('udp')).toEqual({ kind: 'udp', custom: '' });
    expect(parseProtoKind('ICMP')).toEqual({ kind: 'icmp', custom: '' });
    expect(parseProtoKind('gre')).toEqual({ kind: 'custom', custom: 'gre' });
  });

  it('builds empty TLS and Kubernetes defaults', () => {
    expect(emptyTlsNameMatch()).toEqual({ exact: [] });
    expect(emptyTlsHeaders()).toEqual({
      require_present: [],
      deny_present: [],
      exact: {},
      regex: {},
    });
    expect(emptyKubernetesSource()).toEqual({
      integration: '',
      pod_selector: { namespace: '', match_labels: {} },
    });
  });

  it('moves items within bounds and preserves original when out of bounds', () => {
    expect(moveItem(['a', 'b', 'c'], 1, -1)).toEqual(['b', 'a', 'c']);
    const original = ['a', 'b', 'c'];
    expect(moveItem(original, 0, -1)).toBe(original);
  });

  it('duplicates ids and formats validation issues', () => {
    expect(duplicateId('rule-2', ['rule', 'rule-1', 'rule-2'])).toBe('rule-3');
    expect(duplicateId('  ', ['item', 'item-1'])).toBe('item-2');
    expect(
      formatIssues([
        { path: 'a.b', message: 'one' },
        { path: 'c', message: 'two' },
      ])
    ).toEqual(['a.b: one', 'c: two']);
  });
});
