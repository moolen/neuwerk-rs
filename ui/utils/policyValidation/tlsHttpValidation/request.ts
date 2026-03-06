import type { PolicyTlsHttpRequest } from '../../../types';
import { validateHeadersMatcher } from './request/headers';
import { validateMethodMatchers } from './request/methods';
import { validatePathMatcher } from './request/path';
import { validateQueryMatcher } from './request/query';
import { validateTlsNameMatch } from './tlsName';
import type { ValidationIssueLike } from './types';

export function validateTlsHttpRequestMatchers(
  request: PolicyTlsHttpRequest,
  requestPath: string,
  issues: ValidationIssueLike[],
) {
  validateTlsNameMatch(request.host, `${requestPath}.host`, issues);
  validateMethodMatchers(request, requestPath, issues);
  validatePathMatcher(request, requestPath, issues);
  validateQueryMatcher(request, requestPath, issues);
  validateHeadersMatcher(request, requestPath, issues);
}
