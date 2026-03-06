import type { PolicyTlsMatch } from '../../../types';
import { isValidRegex } from '../tlsHttpValidation';
import type { ValidationIssueLike } from './types';

export function hasTlsMetadataMatchers(tls: PolicyTlsMatch): boolean {
  return (
    !!tls.sni ||
    !!tls.server_cn ||
    !!tls.server_san ||
    !!tls.server_dn?.trim() ||
    (tls.fingerprint_sha256 ?? []).length > 0 ||
    (tls.trust_anchors_pem ?? []).length > 0
  );
}

export function validateTlsServerDn(
  tls: PolicyTlsMatch,
  tlsPath: string,
  issues: ValidationIssueLike[]
) {
  if (tls.server_dn === undefined) return;
  const serverDn = tls.server_dn.trim();
  if (!serverDn) {
    issues.push({
      path: `${tlsPath}.server_dn`,
      message: 'server_dn cannot be empty',
    });
    return;
  }
  if (!isValidRegex(serverDn)) {
    issues.push({
      path: `${tlsPath}.server_dn`,
      message: 'server_dn must be a valid regex',
    });
  }
}

export function validateTlsFingerprints(
  tls: PolicyTlsMatch,
  tlsPath: string,
  issues: ValidationIssueLike[]
) {
  for (let index = 0; index < (tls.fingerprint_sha256 ?? []).length; index += 1) {
    const fingerprint = tls.fingerprint_sha256[index].replace(/[\s:]/g, '');
    if (!/^[0-9a-fA-F]{64}$/.test(fingerprint)) {
      issues.push({
        path: `${tlsPath}.fingerprint_sha256[${index}]`,
        message: 'Fingerprint must be 64 hex chars (colons allowed)',
      });
    }
  }
}

export function validateTlsTrustAnchors(
  tls: PolicyTlsMatch,
  tlsPath: string,
  issues: ValidationIssueLike[]
) {
  for (let index = 0; index < (tls.trust_anchors_pem ?? []).length; index += 1) {
    const pem = tls.trust_anchors_pem[index].trim();
    if (!pem) {
      issues.push({
        path: `${tlsPath}.trust_anchors_pem[${index}]`,
        message: 'Trust anchor entry cannot be empty',
      });
      continue;
    }
    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
      issues.push({
        path: `${tlsPath}.trust_anchors_pem[${index}]`,
        message: 'Trust anchor must contain a PEM certificate',
      });
    }
  }
}
