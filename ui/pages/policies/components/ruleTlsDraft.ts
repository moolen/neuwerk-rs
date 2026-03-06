import type {
  PolicyCreateRequest,
  PolicyTls13Uninspectable,
  PolicyTlsMatch,
  PolicyTlsMode,
} from '../../../types';
import { emptyTlsHeaders } from '../helpers';
import type { UpdateDraft } from './formTypes';

export function mutateRuleTls(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  mutator: (tls: PolicyTlsMatch) => void
): void {
  updateDraft((next: PolicyCreateRequest) => {
    const tls = next.policy.source_groups[groupIndex]?.rules[ruleIndex]?.match.tls;
    if (!tls) {
      return;
    }
    mutator(tls);
  });
}

export function defaultRuleTlsMatch(): PolicyTlsMatch {
  return {
    mode: 'metadata',
    fingerprint_sha256: [],
    trust_anchors_pem: [],
    tls13_uninspectable: 'deny',
  };
}

export function applyRuleTlsMode(tls: PolicyTlsMatch, mode: PolicyTlsMode): void {
  tls.mode = mode;
  if (mode === 'intercept') {
    delete tls.sni;
    delete tls.server_cn;
    delete tls.server_san;
    delete tls.server_dn;
    tls.fingerprint_sha256 = [];
    tls.trust_anchors_pem = [];
    tls.http = tls.http ?? {
      request: {
        host: { exact: [] },
        methods: [],
        path: { exact: [], prefix: [] },
        query: { keys_present: [], key_values_exact: {}, key_values_regex: {} },
        headers: emptyTlsHeaders(),
      },
    };
    return;
  }
  delete tls.http;
}

export function toggleRuleTls(updateDraft: UpdateDraft, groupIndex: number, ruleIndex: number): void {
  updateDraft((next: PolicyCreateRequest) => {
    const rule = next.policy.source_groups[groupIndex]?.rules[ruleIndex];
    if (!rule) {
      return;
    }
    if (rule.match.tls) {
      delete rule.match.tls;
      return;
    }
    rule.match.tls = defaultRuleTlsMatch();
  });
}

export function setRuleTlsMode(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  mode: PolicyTlsMode
): void {
  mutateRuleTls(updateDraft, groupIndex, ruleIndex, (tls) => {
    applyRuleTlsMode(tls, mode);
  });
}

export function setRuleTls13Uninspectable(
  updateDraft: UpdateDraft,
  groupIndex: number,
  ruleIndex: number,
  value: PolicyTls13Uninspectable
): void {
  mutateRuleTls(updateDraft, groupIndex, ruleIndex, (tls) => {
    tls.tls13_uninspectable = value;
  });
}
