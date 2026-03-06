import { describe, expect, it } from 'vitest';

import type { PolicyTlsMatch } from '../../types';
import { validateRuleTlsMatch } from './tlsMatchValidation';

interface Issue {
  path: string;
  message: string;
}

function baseTls(overrides: Partial<PolicyTlsMatch> = {}): PolicyTlsMatch {
  return {
    mode: 'metadata',
    fingerprint_sha256: [],
    trust_anchors_pem: [],
    ...overrides,
  };
}

describe('validateRuleTlsMatch', () => {
  it('requires tcp or any protocol', () => {
    const issues: Issue[] = [];
    validateRuleTlsMatch(baseTls(), 'rule.match.tls', 'udp', issues);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'rule.match.tls',
          message: 'TLS match requires proto tcp or any',
        }),
      ])
    );
  });

  it('validates server DN, fingerprints, and trust anchors', () => {
    const issues: Issue[] = [];
    validateRuleTlsMatch(
      baseTls({
        server_dn: '[',
        fingerprint_sha256: ['12:34'],
        trust_anchors_pem: ['', 'not-a-cert'],
      }),
      'rule.match.tls',
      'tcp',
      issues
    );

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'rule.match.tls.server_dn',
          message: 'server_dn must be a valid regex',
        }),
        expect.objectContaining({
          path: 'rule.match.tls.fingerprint_sha256[0]',
          message: 'Fingerprint must be 64 hex chars (colons allowed)',
        }),
        expect.objectContaining({
          path: 'rule.match.tls.trust_anchors_pem[0]',
          message: 'Trust anchor entry cannot be empty',
        }),
        expect.objectContaining({
          path: 'rule.match.tls.trust_anchors_pem[1]',
          message: 'Trust anchor must contain a PEM certificate',
        }),
      ])
    );
  });

  it('enforces tls mode semantics', () => {
    const interceptIssues: Issue[] = [];
    validateRuleTlsMatch(
      baseTls({
        mode: 'intercept',
        sni: { exact: ['api.example.com'] },
      }),
      'rule.match.tls',
      'tcp',
      interceptIssues
    );
    expect(interceptIssues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'rule.match.tls',
          message: 'tls.mode intercept cannot be combined with metadata matchers',
        }),
        expect.objectContaining({
          path: 'rule.match.tls',
          message: 'tls.mode intercept requires tls.http constraints',
        }),
      ])
    );

    const metadataIssues: Issue[] = [];
    validateRuleTlsMatch(
      baseTls({
        mode: 'metadata',
        http: { request: { methods: [] } },
      }),
      'rule.match.tls',
      'tcp',
      metadataIssues
    );
    expect(metadataIssues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'rule.match.tls',
          message: 'tls.http is only valid when tls.mode is intercept',
        }),
      ])
    );
  });

  it('accepts valid intercept configuration', () => {
    const issues: Issue[] = [];
    validateRuleTlsMatch(
      baseTls({
        mode: 'intercept',
        http: {
          request: {
            host: { exact: ['api.example.com'] },
            methods: ['GET'],
            path: { exact: [], prefix: ['/v1/'] },
          },
        },
      }),
      'rule.match.tls',
      'tcp',
      issues
    );
    expect(issues).toEqual([]);
  });
});
