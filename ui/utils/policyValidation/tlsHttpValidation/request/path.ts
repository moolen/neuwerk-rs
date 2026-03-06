import type { PolicyTlsHttpRequest } from '../../../../types';
import { isValidRegex } from '../regex';
import type { ValidationIssueLike } from '../types';

export function validatePathMatcher(
  request: PolicyTlsHttpRequest,
  requestPath: string,
  issues: ValidationIssueLike[],
): void {
  if (!request.path) return;
  const hasPath =
    (request.path.exact ?? []).some((value) => !!value.trim()) ||
    (request.path.prefix ?? []).some((value) => !!value.trim()) ||
    !!request.path.regex?.trim();
  if (!hasPath) {
    issues.push({
      path: `${requestPath}.path`,
      message: 'Path matcher cannot be empty',
    });
  }
  if (request.path.regex?.trim() && !isValidRegex(request.path.regex.trim())) {
    issues.push({
      path: `${requestPath}.path.regex`,
      message: 'Invalid regex',
    });
  }
}
