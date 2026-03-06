import type {
  PolicyCreateRequest,
  PolicyTlsHttpHeadersMatch,
  PolicyTlsHttpPathMatch,
  PolicyTlsHttpQueryMatch,
  PolicyTlsHttpRequest,
} from '../../../types';
import { emptyTlsHeaders } from '../helpers';
import type { UpdateDraft } from './formTypes';

function emptyTlsQuery(): PolicyTlsHttpQueryMatch {
  return {
    keys_present: [],
    key_values_exact: {},
    key_values_regex: {},
  };
}

export function ensureTlsRequestQuery(request: PolicyTlsHttpRequest): PolicyTlsHttpQueryMatch {
  request.query = request.query ?? emptyTlsQuery();
  return request.query;
}

export function ensureTlsRequestHeaders(request: PolicyTlsHttpRequest): PolicyTlsHttpHeadersMatch {
  request.headers = request.headers ?? emptyTlsHeaders();
  return request.headers;
}

export function ensureTlsRequestPath(request: PolicyTlsHttpRequest): PolicyTlsHttpPathMatch {
  request.path = request.path ?? { exact: [], prefix: [] };
  return request.path;
}

export function mutateTlsInterceptRequest(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  mutator: (request: PolicyTlsHttpRequest) => void
): void {
  updateDraft((next: PolicyCreateRequest) => {
    const request = next.policy.source_groups[groupIndex]?.rules[ruleIndex]?.match.tls?.http?.request;
    if (!request) {
      return;
    }
    mutator(request);
  });
}
