import { textToList } from '../helpers';

export type StringListMap = Record<string, string[]>;

export function createStringListMapKey(nowMs: number = Date.now()): string {
  return `key_${nowMs}`;
}

export function addStringListMapRow(
  value: StringListMap,
  nowMs: number = Date.now(),
): StringListMap {
  const key = createStringListMapKey(nowMs);
  return {
    ...value,
    [key]: [],
  };
}

export function removeStringListMapRow(
  value: StringListMap,
  key: string,
): StringListMap {
  const next = { ...value };
  delete next[key];
  return next;
}

export function renameStringListMapRow(
  value: StringListMap,
  oldKey: string,
  nextKeyRaw: string,
  nowMs: number = Date.now(),
): StringListMap {
  const nextKey = nextKeyRaw.trim() || createStringListMapKey(nowMs);
  const next: StringListMap = {};
  for (const [key, entryValue] of Object.entries(value)) {
    if (key === oldKey) {
      next[nextKey] = entryValue;
    } else {
      next[key] = entryValue;
    }
  }
  return next;
}

export function updateStringListMapRow(
  value: StringListMap,
  key: string,
  nextValueRaw: string,
): StringListMap {
  return {
    ...value,
    [key]: textToList(nextValueRaw),
  };
}
