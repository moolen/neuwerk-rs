import { describe, expect, it } from 'vitest';

import { canRevokeToken, formatTokenTimestamp } from './tokenTableHelpers';

describe('tokenTableHelpers', () => {
  it('formats valid timestamps', () => {
    const value = '2026-03-05T10:11:12Z';
    expect(formatTokenTimestamp(value)).toBe(new Date(value).toLocaleString());
  });

  it('returns N/A for missing timestamps', () => {
    expect(formatTokenTimestamp()).toBe('N/A');
    expect(formatTokenTimestamp(null)).toBe('N/A');
  });

  it('returns N/A for invalid timestamps', () => {
    expect(formatTokenTimestamp('not-a-date')).toBe('N/A');
  });

  it('only allows revocation for active tokens', () => {
    expect(canRevokeToken('active')).toBe(true);
    expect(canRevokeToken('revoked')).toBe(false);
  });
});
