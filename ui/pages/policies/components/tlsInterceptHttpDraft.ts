import type { PolicyCreateRequest } from '../../../types';
import { emptyTlsHeaders } from '../helpers';

function tlsAt(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
) {
  return draft.policy.source_groups[groupIndex]?.rules[ruleIndex]?.match.tls;
}

export function enableTlsInterceptRequest(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
): void {
  const tls = tlsAt(draft, groupIndex, ruleIndex);
  if (!tls) return;
  tls.http = tls.http ?? {};
  tls.http.request = tls.http.request ?? {
    host: { exact: [] },
    methods: [],
    path: { exact: [], prefix: [] },
    query: { keys_present: [], key_values_exact: {}, key_values_regex: {} },
    headers: emptyTlsHeaders(),
  };
}

export function disableTlsInterceptRequest(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
): void {
  const tls = tlsAt(draft, groupIndex, ruleIndex);
  if (!tls?.http) return;
  delete tls.http.request;
}

export function enableTlsInterceptResponse(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
): void {
  const tls = tlsAt(draft, groupIndex, ruleIndex);
  if (!tls) return;
  tls.http = tls.http ?? {};
  tls.http.response = tls.http.response ?? {
    headers: emptyTlsHeaders(),
  };
}

export function disableTlsInterceptResponse(
  draft: PolicyCreateRequest,
  groupIndex: number,
  ruleIndex: number,
): void {
  const tls = tlsAt(draft, groupIndex, ruleIndex);
  if (!tls?.http) return;
  delete tls.http.response;
}
