import type { PolicyTlsMatch } from '../../../types';
import type { ValidationIssueLike } from './types';

export function validateTlsMode(
  tls: PolicyTlsMatch,
  tlsPath: string,
  hasMetadataMatchers: boolean,
  issues: ValidationIssueLike[]
) {
  const tlsMode = tls.mode ?? 'metadata';
  const hasHttp = !!tls.http;

  if (tls.http) {
    const hasRequest = !!tls.http.request;
    const hasResponse = !!tls.http.response;
    if (!hasRequest && !hasResponse) {
      issues.push({
        path: `${tlsPath}.http`,
        message: 'tls.http requires request and/or response constraints',
      });
    }
  }

  if (tlsMode === 'intercept') {
    if (hasMetadataMatchers) {
      issues.push({
        path: tlsPath,
        message: 'tls.mode intercept cannot be combined with metadata matchers',
      });
    }
    if (!hasHttp) {
      issues.push({
        path: tlsPath,
        message: 'tls.mode intercept requires tls.http constraints',
      });
    }
    return;
  }

  if (tlsMode === 'metadata') {
    if (hasHttp) {
      issues.push({
        path: tlsPath,
        message: 'tls.http is only valid when tls.mode is intercept',
      });
    }
    return;
  }

  issues.push({
    path: `${tlsPath}.mode`,
    message: 'tls.mode must be metadata or intercept',
  });
}
