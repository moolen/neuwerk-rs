import { describe, expect, it } from 'vitest';

import { normalizeTlsMatch, normalizeTlsNameMatch } from './tls';

describe('policyModel normalize tls helpers', () => {
  it('normalizes tls name matcher from string/list/object forms', () => {
    expect(normalizeTlsNameMatch(' ^foo$ ')).toEqual({ exact: [], regex: '^foo$' });
    expect(normalizeTlsNameMatch([' foo ', ''])).toEqual({ exact: ['foo'] });
    expect(normalizeTlsNameMatch({ exact: [' bar '], regex: ' ^bar$ ' })).toEqual({
      exact: ['bar'],
      regex: '^bar$',
    });
    expect(normalizeTlsNameMatch({ exact: [' '], regex: ' ' })).toBeUndefined();
  });

  it('normalizes intercept TLS HTTP request and response matchers', () => {
    const tls = normalizeTlsMatch({
      mode: 'intercept',
      http: {
        request: {
          methods: ['get', ' post '],
          path: { prefix: [' /api '] },
          headers: { exact: { accept: [' application/json '] } },
        },
        response: {
          headers: { regex: { server: ' ^nginx$ ' } },
        },
      },
      fingerprint_sha256: [],
      trust_anchors_pem: [],
    });

    expect(tls).toEqual({
      mode: 'intercept',
      fingerprint_sha256: [],
      trust_anchors_pem: [],
      tls13_uninspectable: 'deny',
      http: {
        request: {
          methods: ['GET', 'POST'],
          path: { exact: [], prefix: ['/api'] },
          headers: {
            require_present: [],
            deny_present: [],
            exact: { accept: ['application/json'] },
            regex: {},
          },
        },
        response: {
          headers: {
            require_present: [],
            deny_present: [],
            exact: {},
            regex: { server: '^nginx$' },
          },
        },
      },
    });
  });

  it('drops empty default metadata-only TLS objects', () => {
    expect(
      normalizeTlsMatch({
        mode: 'metadata',
        fingerprint_sha256: [],
        trust_anchors_pem: [],
        tls13_uninspectable: 'deny',
      }),
    ).toBeUndefined();
  });
});
