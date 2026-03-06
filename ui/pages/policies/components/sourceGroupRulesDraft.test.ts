import { describe, expect, it } from 'vitest';

import { selectedRuleTemplate, withGroupTemplate } from './sourceGroupRulesDraft';

describe('sourceGroupRulesDraft', () => {
  it('falls back to l4_allow when group template is unset', () => {
    expect(selectedRuleTemplate({}, 3)).toBe('l4_allow');
  });

  it('returns configured template for group', () => {
    expect(selectedRuleTemplate({ 1: 'dns_allow' }, 1)).toBe('dns_allow');
  });

  it('sets group template while preserving other entries', () => {
    const next = withGroupTemplate({ 0: 'l4_allow', 1: 'dns_allow' }, 1, 'tls_metadata');
    expect(next).toEqual({ 0: 'l4_allow', 1: 'tls_metadata' });
  });
});
