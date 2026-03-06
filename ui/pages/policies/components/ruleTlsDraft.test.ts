import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../../types';
import {
  applyRuleTlsMode,
  mutateRuleTls,
  setRuleTls13Uninspectable,
  setRuleTlsMode,
  toggleRuleTls,
} from './ruleTlsDraft';

function makeDraft(withTls = true): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_action: 'allow',
      source_groups: [
        {
          id: 'g1',
          priority: 100,
          default_action: 'allow',
          sources: { cidrs: ['10.0.0.0/24'], ips: [], kubernetes: [] },
          rules: [
            {
              id: 'r1',
              action: 'allow',
              match: {
                dst_cidrs: [],
                dst_ips: [],
                src_ports: [],
                dst_ports: [],
                icmp_types: [],
                icmp_codes: [],
                tls: withTls
                  ? {
                      mode: 'metadata',
                      sni: { exact: ['example.com'] },
                      server_cn: { exact: ['example.com'] },
                      fingerprint_sha256: ['abc'],
                      trust_anchors_pem: ['pem'],
                      tls13_uninspectable: 'deny',
                    }
                  : undefined,
              },
            },
          ],
        },
      ],
    },
  };
}

describe('ruleTlsDraft', () => {
  it('mutates existing tls match and no-ops when missing', () => {
    const withTls = makeDraft(true);
    const withoutTls = makeDraft(false);
    const updateWithTls = (mutator: (next: PolicyCreateRequest) => void) => mutator(withTls);
    const updateWithoutTls = (mutator: (next: PolicyCreateRequest) => void) => mutator(withoutTls);

    mutateRuleTls(updateWithTls, 0, 0, (tls) => {
      tls.server_dn = 'CN=example';
    });
    mutateRuleTls(updateWithoutTls, 0, 0, (tls) => {
      tls.server_dn = 'unused';
    });

    expect(withTls.policy.source_groups[0].rules[0].match.tls?.server_dn).toBe('CN=example');
    expect(withoutTls.policy.source_groups[0].rules[0].match.tls).toBeUndefined();
  });

  it('toggleRuleTls adds defaults and removes existing tls', () => {
    const withoutTls = makeDraft(false);
    const withTls = makeDraft(true);
    const updateWithoutTls = (mutator: (next: PolicyCreateRequest) => void) => mutator(withoutTls);
    const updateWithTls = (mutator: (next: PolicyCreateRequest) => void) => mutator(withTls);

    toggleRuleTls(updateWithoutTls, 0, 0);
    toggleRuleTls(updateWithTls, 0, 0);

    expect(withoutTls.policy.source_groups[0].rules[0].match.tls).toEqual({
      mode: 'metadata',
      fingerprint_sha256: [],
      trust_anchors_pem: [],
      tls13_uninspectable: 'deny',
    });
    expect(withTls.policy.source_groups[0].rules[0].match.tls).toBeUndefined();
  });

  it('applyRuleTlsMode switches to intercept and clears metadata fields', () => {
    const draft = makeDraft(true);
    const tls = draft.policy.source_groups[0].rules[0].match.tls!;

    applyRuleTlsMode(tls, 'intercept');

    expect(tls.mode).toBe('intercept');
    expect(tls.sni).toBeUndefined();
    expect(tls.server_cn).toBeUndefined();
    expect(tls.server_san).toBeUndefined();
    expect(tls.server_dn).toBeUndefined();
    expect(tls.fingerprint_sha256).toEqual([]);
    expect(tls.trust_anchors_pem).toEqual([]);
    expect(tls.http?.request?.path).toEqual({ exact: [], prefix: [] });
  });

  it('setRuleTlsMode clears intercept http when returning to metadata', () => {
    const draft = makeDraft(true);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);
    setRuleTlsMode(updateDraft, 0, 0, 'intercept');
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http).toBeDefined();

    setRuleTlsMode(updateDraft, 0, 0, 'metadata');

    expect(draft.policy.source_groups[0].rules[0].match.tls?.mode).toBe('metadata');
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http).toBeUndefined();
  });

  it('setRuleTls13Uninspectable updates tls policy in place', () => {
    const draft = makeDraft(true);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    setRuleTls13Uninspectable(updateDraft, 0, 0, 'allow');

    expect(draft.policy.source_groups[0].rules[0].match.tls?.tls13_uninspectable).toBe('allow');
  });
});
