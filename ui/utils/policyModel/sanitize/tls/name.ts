import type { PolicyTlsNameMatch } from '../../../../types';
import { sanitizeStringList } from '../shared';

export function sanitizeTlsNameMatch(value?: PolicyTlsNameMatch): PolicyTlsNameMatch | undefined {
  if (!value) return undefined;
  const exact = sanitizeStringList(value.exact);
  const regex = value.regex?.trim();
  if (!exact.length && !regex) return undefined;
  return {
    exact,
    ...(regex ? { regex } : {}),
  };
}
