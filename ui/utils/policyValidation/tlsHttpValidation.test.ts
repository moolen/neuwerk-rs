import { describe, expect, it } from 'vitest';

import type { PolicyTlsHttpRequest } from '../../types';
import {
  isValidRegex,
  validateTlsHttpRequestMatchers,
  validateTlsHttpResponseHeadersMatchers,
  validateTlsNameMatch,
} from './tlsHttpValidation';

function baseRequest(): PolicyTlsHttpRequest {
  return {
    methods: ['GET'],
  };
}

describe('tlsHttpValidation', () => {
  it('validates regex patterns', () => {
    expect(isValidRegex('^foo$')).toBe(true);
    expect(isValidRegex('[')).toBe(false);
  });

  it('flags empty/invalid TLS name matcher', () => {
    const issues: { path: string; message: string }[] = [];
    validateTlsNameMatch({ exact: [' '], regex: ' ' }, 'tls.sni', issues);
    validateTlsNameMatch({ exact: [], regex: '[' }, 'tls.server_cn', issues);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'tls.sni',
          message: 'Matcher cannot be empty; set exact and/or regex',
        }),
        expect.objectContaining({
          path: 'tls.server_cn.regex',
          message: 'Invalid regex',
        }),
      ]),
    );
  });

  it('flags invalid request matchers across methods/path/query/headers', () => {
    const request: PolicyTlsHttpRequest = {
      ...baseRequest(),
      methods: ['GET', ' '],
      path: { exact: [' '], prefix: [''], regex: '[' },
      query: {
        keys_present: [' '],
        key_values_exact: { ' ': [''], user: [' '] },
        key_values_regex: { ' ': '', region: '[' },
      },
      headers: {
        require_present: [' '],
        deny_present: [' '],
        exact: { ' ': [''], host: [' '] },
        regex: { ' ': '', 'x-team': '[' },
      },
    };
    const issues: { path: string; message: string }[] = [];

    validateTlsHttpRequestMatchers(request, 'tls.http.request', issues);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'tls.http.request.methods[1]',
          message: 'HTTP method cannot be empty',
        }),
        expect.objectContaining({
          path: 'tls.http.request.path.regex',
          message: 'Invalid regex',
        }),
        expect.objectContaining({
          path: 'tls.http.request.query.key_values_exact',
          message: 'Exact query matcher key cannot be empty',
        }),
        expect.objectContaining({
          path: 'tls.http.request.query.key_values_regex.region',
          message: 'Invalid regex pattern',
        }),
        expect.objectContaining({
          path: 'tls.http.request.headers.exact',
          message: 'Exact header matcher key cannot be empty',
        }),
        expect.objectContaining({
          path: 'tls.http.request.headers.regex.x-team',
          message: 'Invalid regex',
        }),
      ]),
    );
  });

  it('flags response header matcher emptiness and invalid regex', () => {
    const issues: { path: string; message: string }[] = [];
    validateTlsHttpResponseHeadersMatchers(
      {
        require_present: [' '],
        deny_present: [' '],
        exact: {},
        regex: {
          ' ': '[',
          host: '[',
        },
      },
      'tls.http.response.headers',
      issues,
    );

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'tls.http.response.headers.regex',
          message: 'Regex header matcher key cannot be empty',
        }),
        expect.objectContaining({
          path: 'tls.http.response.headers.regex. ',
          message: 'Invalid regex',
        }),
        expect.objectContaining({
          path: 'tls.http.response.headers.regex.host',
          message: 'Invalid regex',
        }),
      ]),
    );
  });

  it('flags empty query/header response matcher sections', () => {
    const requestIssues: { path: string; message: string }[] = [];
    validateTlsHttpRequestMatchers(
      {
        methods: ['GET'],
        query: {
          keys_present: [],
          key_values_exact: {},
          key_values_regex: {},
        },
        headers: {
          require_present: [],
          deny_present: [],
          exact: {},
          regex: {},
        },
      },
      'tls.http.request',
      requestIssues,
    );

    expect(requestIssues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'tls.http.request.query',
          message: 'Query matcher cannot be empty',
        }),
        expect.objectContaining({
          path: 'tls.http.request.headers',
          message: 'Header matcher cannot be empty',
        }),
      ]),
    );

    const responseIssues: { path: string; message: string }[] = [];
    validateTlsHttpResponseHeadersMatchers(
      {
        require_present: [],
        deny_present: [],
        exact: {},
        regex: {},
      },
      'tls.http.response.headers',
      responseIssues,
    );
    expect(responseIssues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'tls.http.response.headers',
          message: 'Response header matcher cannot be empty',
        }),
      ]),
    );
  });
});
