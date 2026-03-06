import type { PolicyTlsHttpRequest } from '../../../../types';
import type { ValidationIssueLike } from '../types';

export function validateMethodMatchers(
  request: PolicyTlsHttpRequest,
  requestPath: string,
  issues: ValidationIssueLike[],
): void {
  for (let methodIndex = 0; methodIndex < (request.methods ?? []).length; methodIndex += 1) {
    const method = request.methods[methodIndex].trim();
    if (!method) {
      issues.push({
        path: `${requestPath}.methods[${methodIndex}]`,
        message: 'HTTP method cannot be empty',
      });
    }
  }
}
