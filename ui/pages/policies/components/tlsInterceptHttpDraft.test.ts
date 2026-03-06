import { describe, expect, it } from 'vitest';

import { createEmptyPolicyRequest, createEmptyRule, createEmptySourceGroup } from '../../../utils/policyModel';
import {
  disableTlsInterceptRequest,
  disableTlsInterceptResponse,
  enableTlsInterceptRequest,
  enableTlsInterceptResponse,
} from './tlsInterceptHttpDraft';

function buildDraftWithTls() {
  const draft = createEmptyPolicyRequest();
  const group = createEmptySourceGroup('group-1');
  const rule = createEmptyRule('rule-1');
  rule.match.tls = {
    mode: 'intercept',
    fingerprint_sha256: [],
    trust_anchors_pem: [],
  };
  group.rules.push(rule);
  draft.policy.source_groups.push(group);
  return draft;
}

describe('tlsInterceptHttpDraft', () => {
  it('enables request constraints with defaults', () => {
    const draft = buildDraftWithTls();
    enableTlsInterceptRequest(draft, 0, 0);
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.request).toEqual({
      host: { exact: [] },
      methods: [],
      path: { exact: [], prefix: [] },
      query: { keys_present: [], key_values_exact: {}, key_values_regex: {} },
      headers: {
        require_present: [],
        deny_present: [],
        exact: {},
        regex: {},
      },
    });
  });

  it('enables response constraints with defaults', () => {
    const draft = buildDraftWithTls();
    enableTlsInterceptResponse(draft, 0, 0);
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.response).toEqual({
      headers: {
        require_present: [],
        deny_present: [],
        exact: {},
        regex: {},
      },
    });
  });

  it('disables request and response constraints independently', () => {
    const draft = buildDraftWithTls();
    enableTlsInterceptRequest(draft, 0, 0);
    enableTlsInterceptResponse(draft, 0, 0);
    disableTlsInterceptRequest(draft, 0, 0);
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.request).toBeUndefined();
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.response).toBeDefined();
    disableTlsInterceptResponse(draft, 0, 0);
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http?.response).toBeUndefined();
  });

  it('no-ops when indices are out of range', () => {
    const draft = buildDraftWithTls();
    enableTlsInterceptRequest(draft, 1, 0);
    disableTlsInterceptRequest(draft, 1, 0);
    enableTlsInterceptResponse(draft, 0, 1);
    disableTlsInterceptResponse(draft, 0, 1);
    expect(draft.policy.source_groups[0].rules[0].match.tls?.http).toBeUndefined();
  });
});
