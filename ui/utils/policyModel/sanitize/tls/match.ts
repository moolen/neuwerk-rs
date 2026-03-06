import type { PolicyTlsMatch } from '../../../../types';
import { sanitizeStringList } from '../shared';
import { sanitizeHttp } from './http';
import { sanitizeTlsNameMatch } from './name';

export function sanitizeTls(value?: PolicyTlsMatch): PolicyTlsMatch | undefined {
  if (!value) return undefined;
  const mode = value.mode ?? 'metadata';
  const sni = sanitizeTlsNameMatch(value.sni);
  const server_san = sanitizeTlsNameMatch(value.server_san);
  const server_cn = sanitizeTlsNameMatch(value.server_cn);
  const server_dn = value.server_dn?.trim();
  const fingerprint_sha256 = sanitizeStringList(value.fingerprint_sha256);
  const trust_anchors_pem = sanitizeStringList(value.trust_anchors_pem);
  const tls13_uninspectable = value.tls13_uninspectable ?? 'deny';
  const http = sanitizeHttp(value.http);

  const hasAny =
    mode !== 'metadata' ||
    !!sni ||
    !!server_san ||
    !!server_cn ||
    !!server_dn ||
    fingerprint_sha256.length > 0 ||
    trust_anchors_pem.length > 0 ||
    tls13_uninspectable !== 'deny' ||
    !!http;
  if (!hasAny) return undefined;

  return {
    mode,
    ...(sni ? { sni } : {}),
    ...(server_dn ? { server_dn } : {}),
    ...(server_san ? { server_san } : {}),
    ...(server_cn ? { server_cn } : {}),
    ...(fingerprint_sha256.length ? { fingerprint_sha256 } : {}),
    ...(trust_anchors_pem.length ? { trust_anchors_pem } : {}),
    ...(tls13_uninspectable ? { tls13_uninspectable } : {}),
    ...(http ? { http } : {}),
  };
}
