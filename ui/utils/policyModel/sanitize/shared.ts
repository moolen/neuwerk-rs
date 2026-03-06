function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function sanitizeStringList(value: readonly string[] | undefined): string[] {
  return (value ?? []).map((entry) => entry.trim()).filter(Boolean);
}

export function sanitizeUppercaseStringList(value: readonly string[] | undefined): string[] {
  return sanitizeStringList(value).map((entry) => entry.toUpperCase());
}

export function sanitizeNumberList(value: readonly number[] | undefined): number[] {
  return (value ?? []).filter((entry) => Number.isFinite(entry));
}

export function sanitizeStringMap(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(value)) {
    if (typeof rawValue !== 'string') continue;
    const normalizedKey = key.trim();
    const normalizedValue = rawValue.trim();
    if (!normalizedKey || !normalizedValue) continue;
    out[normalizedKey] = normalizedValue;
  }
  return out;
}

export function sanitizeStringListMap(
  value: Record<string, string[] | undefined> | undefined,
): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [key, rawValues] of Object.entries(value ?? {})) {
    const normalizedKey = key.trim();
    const normalizedValues = sanitizeStringList(rawValues ?? []);
    if (!normalizedKey || !normalizedValues.length) continue;
    out[normalizedKey] = normalizedValues;
  }
  return out;
}
