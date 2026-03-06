import type { PolicyTlsMatch } from '../../../../types';
import { asString, asStringList, asTls13Mode, asTlsMode, isObject } from '../shared';
import { normalizeTlsHttp } from './http';
import { normalizeTlsNameMatch } from './name';

export function normalizeTlsMatch(value: unknown): PolicyTlsMatch | undefined {
  if (!isObject(value)) return undefined;
  const mode = asTlsMode(value.mode);
  const sni = normalizeTlsNameMatch(value.sni);
  const server_cn = normalizeTlsNameMatch(value.server_cn);
  const server_san = normalizeTlsNameMatch(value.server_san);
  const server_dn = asString(value.server_dn);
  const fingerprint_sha256 = asStringList(value.fingerprint_sha256);
  const trust_anchors_pem = asStringList(value.trust_anchors_pem);
  const tls13_uninspectable = asTls13Mode(value.tls13_uninspectable);
  const http = normalizeTlsHttp(value.http);

  const hasAnyField =
    mode !== 'metadata' ||
    !!sni ||
    !!server_cn ||
    !!server_san ||
    !!server_dn ||
    fingerprint_sha256.length > 0 ||
    trust_anchors_pem.length > 0 ||
    tls13_uninspectable !== 'deny' ||
    !!http;
  if (!hasAnyField) return undefined;

  return {
    mode,
    ...(sni ? { sni } : {}),
    ...(server_dn ? { server_dn } : {}),
    ...(server_san ? { server_san } : {}),
    ...(server_cn ? { server_cn } : {}),
    fingerprint_sha256,
    trust_anchors_pem,
    tls13_uninspectable,
    ...(http ? { http } : {}),
  };
}
