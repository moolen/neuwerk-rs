import type { PolicyTlsHttpRequest } from '../../../../types';
import { isValidRegex } from '../regex';
import type { ValidationIssueLike } from '../types';

export function validateHeadersMatcher(
  request: PolicyTlsHttpRequest,
  requestPath: string,
  issues: ValidationIssueLike[],
): void {
  if (!request.headers) return;
  const hasHeaders =
    (request.headers.require_present ?? []).some((value) => !!value.trim()) ||
    (request.headers.deny_present ?? []).some((value) => !!value.trim()) ||
    Object.keys(request.headers.exact ?? {}).length > 0 ||
    Object.keys(request.headers.regex ?? {}).length > 0;
  if (!hasHeaders) {
    issues.push({
      path: `${requestPath}.headers`,
      message: 'Header matcher cannot be empty',
    });
  }
  for (const [key, values] of Object.entries(request.headers.exact ?? {})) {
    if (!key.trim()) {
      issues.push({
        path: `${requestPath}.headers.exact`,
        message: 'Exact header matcher key cannot be empty',
      });
    }
    if (!values.length || !values.some((value) => !!value.trim())) {
      issues.push({
        path: `${requestPath}.headers.exact.${key}`,
        message: 'Exact header matcher values cannot be empty',
      });
    }
  }
  for (const [key, pattern] of Object.entries(request.headers.regex ?? {})) {
    if (!key.trim()) {
      issues.push({
        path: `${requestPath}.headers.regex`,
        message: 'Regex header matcher key cannot be empty',
      });
    }
    if (!pattern.trim()) {
      issues.push({
        path: `${requestPath}.headers.regex.${key}`,
        message: 'Regex header pattern cannot be empty',
      });
    } else if (!isValidRegex(pattern.trim())) {
      issues.push({
        path: `${requestPath}.headers.regex.${key}`,
        message: 'Invalid regex',
      });
    }
  }
}
