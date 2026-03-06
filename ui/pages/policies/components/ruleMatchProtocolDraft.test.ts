import { describe, expect, it } from 'vitest';

import type { PolicyRuleMatch } from '../../../types';
import {
  applyRuleMatchProtoSelection,
  normalizeRuleMatchDnsHostname,
} from './ruleMatchProtocolDraft';

function baseMatch(): PolicyRuleMatch {
  return {
    dst_cidrs: [],
    dst_ips: [],
    src_ports: [],
    dst_ports: [],
    icmp_types: [],
    icmp_codes: [],
  };
}

describe('ruleMatchProtocolDraft', () => {
  it('sets known protocol values', () => {
    const match = baseMatch();
    applyRuleMatchProtoSelection(match, 'tcp', '');
    expect(match.proto).toBe('tcp');
  });

  it('sets custom protocol with fallback default', () => {
    const withCustom = baseMatch();
    const withoutCustom = baseMatch();

    applyRuleMatchProtoSelection(withCustom, 'custom', '47');
    applyRuleMatchProtoSelection(withoutCustom, 'custom', '');

    expect(withCustom.proto).toBe('47');
    expect(withoutCustom.proto).toBe('6');
  });

  it('clears protocol for any', () => {
    const match = baseMatch();
    match.proto = 'udp';

    applyRuleMatchProtoSelection(match, 'any', '');

    expect(match.proto).toBeUndefined();
  });

  it('normalizes dns hostname by trimming empties', () => {
    expect(normalizeRuleMatchDnsHostname('example\\.com')).toBe('example\\.com');
    expect(normalizeRuleMatchDnsHostname('   ')).toBeUndefined();
  });
});
