import type { PolicyTlsNameMatch } from '../../../../types';
import { asString, asStringList, isObject } from '../shared';

export function normalizeTlsNameMatch(value: unknown): PolicyTlsNameMatch | undefined {
  if (typeof value === 'string') {
    const regex = value.trim();
    return regex ? { exact: [], regex } : undefined;
  }
  if (Array.isArray(value)) {
    const exact = asStringList(value);
    return exact.length ? { exact } : undefined;
  }
  if (!isObject(value)) return undefined;
  const exact = asStringList(value.exact);
  const regex = asString(value.regex);
  if (!exact.length && !regex) return undefined;
  return {
    exact,
    ...(regex ? { regex } : {}),
  };
}
