import type { PolicyTlsHttpRequest } from '../../../../types';
import { isValidRegex } from '../regex';
import type { ValidationIssueLike } from '../types';

export function validateQueryMatcher(
  request: PolicyTlsHttpRequest,
  requestPath: string,
  issues: ValidationIssueLike[],
): void {
  if (!request.query) return;
  const hasQuery =
    (request.query.keys_present ?? []).some((value) => !!value.trim()) ||
    Object.keys(request.query.key_values_exact ?? {}).length > 0 ||
    Object.keys(request.query.key_values_regex ?? {}).length > 0;
  if (!hasQuery) {
    issues.push({
      path: `${requestPath}.query`,
      message: 'Query matcher cannot be empty',
    });
  }
  for (const [key, values] of Object.entries(request.query.key_values_exact ?? {})) {
    if (!key.trim()) {
      issues.push({
        path: `${requestPath}.query.key_values_exact`,
        message: 'Exact query matcher key cannot be empty',
      });
    }
    if (!values.length || !values.some((value) => !!value.trim())) {
      issues.push({
        path: `${requestPath}.query.key_values_exact.${key}`,
        message: 'Exact query matcher values cannot be empty',
      });
    }
  }
  for (const [key, pattern] of Object.entries(request.query.key_values_regex ?? {})) {
    if (!key.trim()) {
      issues.push({
        path: `${requestPath}.query.key_values_regex`,
        message: 'Regex query matcher key cannot be empty',
      });
    }
    if (!pattern.trim()) {
      issues.push({
        path: `${requestPath}.query.key_values_regex.${key}`,
        message: 'Regex pattern cannot be empty',
      });
    } else if (!isValidRegex(pattern.trim())) {
      issues.push({
        path: `${requestPath}.query.key_values_regex.${key}`,
        message: 'Invalid regex pattern',
      });
    }
  }
}
