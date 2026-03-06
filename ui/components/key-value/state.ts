export type KeyValueMap = Record<string, string>;

export function createTempKey(): string {
  return `__tmp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function renameEntryKey(
  data: KeyValueMap,
  oldKey: string,
  nextKeyRaw: string,
  tempKeyFactory: () => string = createTempKey
): KeyValueMap {
  const next: KeyValueMap = {};
  for (const [k, v] of Object.entries(data)) {
    if (k !== oldKey) {
      next[k] = v;
    }
  }
  next[nextKeyRaw.trim() || tempKeyFactory()] = data[oldKey] ?? '';
  return next;
}

export function setEntryValue(data: KeyValueMap, key: string, nextValue: string): KeyValueMap {
  return {
    ...data,
    [key]: nextValue,
  };
}

export function addEmptyEntry(data: KeyValueMap, tempKeyFactory: () => string = createTempKey): KeyValueMap {
  return {
    ...data,
    [tempKeyFactory()]: '',
  };
}

export function removeEntry(data: KeyValueMap, key: string): KeyValueMap {
  const next = { ...data };
  delete next[key];
  return next;
}

export function displayKey(rawKey: string): string {
  return rawKey.startsWith('__tmp_') ? '' : rawKey;
}
