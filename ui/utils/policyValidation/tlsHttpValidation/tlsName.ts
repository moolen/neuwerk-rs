import type { PolicyTlsNameMatch } from '../../../types';
import { isValidRegex } from './regex';
import type { ValidationIssueLike } from './types';

export function validateTlsNameMatch(
  value: PolicyTlsNameMatch | undefined,
  basePath: string,
  issues: ValidationIssueLike[],
) {
  if (!value) return;
  const exact = (value.exact ?? []).map((entry) => entry.trim()).filter(Boolean);
  const regex = value.regex?.trim() ?? '';
  if (!exact.length && !regex) {
    issues.push({
      path: basePath,
      message: 'Matcher cannot be empty; set exact and/or regex',
    });
    return;
  }
  if (regex && !isValidRegex(regex)) {
    issues.push({
      path: `${basePath}.regex`,
      message: 'Invalid regex',
    });
  }
}
