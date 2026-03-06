import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest, PolicyTlsHttpRequest } from '../../../types';
import {
  ensureTlsRequestHeaders,
  ensureTlsRequestPath,
  ensureTlsRequestQuery,
  mutateTlsInterceptRequest,
} from './tlsInterceptRequestDraft';

function makeRequestDraft(withRequest = true): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_action: 'allow',
      source_groups: [
        {
          id: 'g1',
          priority: 100,
          default_action: 'allow',
          sources: [{ cidrs: ['10.0.0.0/24'] }],
          rules: [
            {
              id: 'r1',
              action: 'allow',
              match: withRequest
                ? {
                    tls: {
                      mode: 'intercept',
                      server_name: { exact: [] },
                      server_cn: { exact: [] },
                      fingerprint_sha256: [],
                      trust_anchors_pem: [],
                      tls13_uninspectable: 'deny',
                      http: { request: { methods: [] } },
                    },
                  }
                : {},
            },
          ],
        },
      ],
    },
  };
}

describe('tlsInterceptRequestDraft', () => {
  it('initializes and returns query defaults', () => {
    const request: PolicyTlsHttpRequest = { methods: [] };
    expect(ensureTlsRequestQuery(request)).toEqual({
      keys_present: [],
      key_values_exact: {},
      key_values_regex: {},
    });
    expect(ensureTlsRequestQuery(request)).toBe(request.query);
  });

  it('initializes and returns header defaults', () => {
    const request: PolicyTlsHttpRequest = { methods: [] };
    expect(ensureTlsRequestHeaders(request)).toEqual({
      require_present: [],
      deny_present: [],
      exact: {},
      regex: {},
    });
    expect(ensureTlsRequestHeaders(request)).toBe(request.headers);
  });

  it('initializes and returns path defaults', () => {
    const request: PolicyTlsHttpRequest = { methods: [] };
    expect(ensureTlsRequestPath(request)).toEqual({
      exact: [],
      prefix: [],
    });
    expect(ensureTlsRequestPath(request)).toBe(request.path);
  });

  it('mutates request when intercept request exists', () => {
    const draft = makeRequestDraft(true);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    mutateTlsInterceptRequest(updateDraft, 0, 0, (request) => {
      request.methods = ['GET'];
    });

    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.request?.methods).toEqual([
      'GET',
    ]);
  });

  it('is a no-op when intercept request is missing', () => {
    const draft = makeRequestDraft(false);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    expect(() =>
      mutateTlsInterceptRequest(updateDraft, 0, 0, (request) => {
        request.methods = ['GET'];
      })
    ).not.toThrow();
    expect(draft.policy.source_groups[0].rules[0].match.tls).toBeUndefined();
  });
});
