import type { PolicyTlsMatch } from '../../types';
import {
  validateTlsHttpRequestMatchers,
  validateTlsHttpResponseHeadersMatchers,
  validateTlsNameMatch,
} from './tlsHttpValidation';
import {
  hasTlsMetadataMatchers,
  validateTlsFingerprints,
  validateTlsServerDn,
  validateTlsTrustAnchors,
} from './tlsMatchValidation/metadata';
import { validateTlsMode } from './tlsMatchValidation/mode';
import type { ValidationIssueLike } from './tlsMatchValidation/types';

export function validateRuleTlsMatch(
  tls: PolicyTlsMatch,
  tlsPath: string,
  proto: string,
  issues: ValidationIssueLike[]
) {
  if (proto !== 'tcp' && proto !== 'any') {
    issues.push({
      path: tlsPath,
      message: 'TLS match requires proto tcp or any',
    });
  }

  const hasMetadataMatchers = hasTlsMetadataMatchers(tls);

  validateTlsNameMatch(tls.sni, `${tlsPath}.sni`, issues);
  validateTlsNameMatch(tls.server_cn, `${tlsPath}.server_cn`, issues);
  validateTlsNameMatch(tls.server_san, `${tlsPath}.server_san`, issues);
  validateTlsServerDn(tls, tlsPath, issues);
  validateTlsFingerprints(tls, tlsPath, issues);
  validateTlsTrustAnchors(tls, tlsPath, issues);
  validateTlsMode(tls, tlsPath, hasMetadataMatchers, issues);

  if (!tls.http) return;

  if (tls.http.request) {
    const requestPath = `${tlsPath}.http.request`;
    validateTlsHttpRequestMatchers(tls.http.request, requestPath, issues);
  }

  if (tls.http.response?.headers) {
    validateTlsHttpResponseHeadersMatchers(
      tls.http.response.headers,
      `${tlsPath}.http.response.headers`,
      issues
    );
  }
}
