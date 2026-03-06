import { afterEach, describe, expect, it, vi } from 'vitest';

import { formatBytes, formatEpoch, formatNumber } from './helpers';

describe('dashboard helpers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('formats counters using K/M/B suffixes', () => {
    expect(formatNumber(999)).toBe('999');
    expect(formatNumber(1_000)).toBe('1.0K');
    expect(formatNumber(1_250_000)).toBe('1.3M');
    expect(formatNumber(3_500_000_000)).toBe('3.5B');
  });

  it('formats byte counters using size suffixes', () => {
    expect(formatBytes(999)).toBe('999 B');
    expect(formatBytes(1_500)).toBe('1.50 KB');
    expect(formatBytes(5_200_000)).toBe('5.20 MB');
    expect(formatBytes(9_000_000_000)).toBe('9.00 GB');
  });

  it('formats unix epoch values and handles empty epoch', () => {
    expect(formatEpoch(0)).toBe('N/A');

    const spy = vi.spyOn(Date.prototype, 'toLocaleString').mockReturnValue('formatted');
    expect(formatEpoch(1_700_000_000)).toBe('formatted');
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
