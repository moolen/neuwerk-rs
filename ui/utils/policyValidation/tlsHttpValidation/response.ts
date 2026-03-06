import type { PolicyTlsHttpHeadersMatch } from '../../../types';
import { isValidRegex } from './regex';
import type { ValidationIssueLike } from './types';

export function validateTlsHttpResponseHeadersMatchers(
  headers: PolicyTlsHttpHeadersMatch,
  headersPath: string,
  issues: ValidationIssueLike[],
) {
  const hasHeaders =
    (headers.require_present ?? []).some((value) => !!value.trim()) ||
    (headers.deny_present ?? []).some((value) => !!value.trim()) ||
    Object.keys(headers.exact ?? {}).length > 0 ||
    Object.keys(headers.regex ?? {}).length > 0;
  if (!hasHeaders) {
    issues.push({
      path: headersPath,
      message: 'Response header matcher cannot be empty',
    });
  }
  for (const [key, pattern] of Object.entries(headers.regex ?? {})) {
    if (!key.trim()) {
      issues.push({
        path: `${headersPath}.regex`,
        message: 'Regex header matcher key cannot be empty',
      });
    }
    if (pattern.trim() && !isValidRegex(pattern.trim())) {
      issues.push({
        path: `${headersPath}.regex.${key}`,
        message: 'Invalid regex',
      });
    }
  }
}
