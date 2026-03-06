import { describe, expect, it } from 'vitest';

import type { DNSCacheEntry } from '../../types';
import { filterDNSCacheEntries, formatDNSCacheTimestamp } from './helpers';

const ENTRIES: DNSCacheEntry[] = [
  {
    hostname: 'api.example.com',
    ips: ['10.0.0.1', '2001:db8::1'],
    last_seen: 1_700_000_000,
  },
  {
    hostname: 'db.internal.local',
    ips: ['192.168.10.45'],
    last_seen: 1_700_000_100,
  },
];

describe('filterDNSCacheEntries', () => {
  it('matches hostnames case-insensitively', () => {
    expect(filterDNSCacheEntries(ENTRIES, 'API.EXAMPLE')).toEqual([ENTRIES[0]]);
  });

  it('matches ip addresses case-insensitively', () => {
    expect(filterDNSCacheEntries(ENTRIES, '192.168.10')).toEqual([ENTRIES[1]]);
  });

  it('returns all entries for empty search', () => {
    expect(filterDNSCacheEntries(ENTRIES, '')).toEqual(ENTRIES);
  });
});

describe('formatDNSCacheTimestamp', () => {
  it('returns N/A for zero timestamps', () => {
    expect(formatDNSCacheTimestamp(0)).toBe('N/A');
  });

  it('returns a non-empty formatted date for valid timestamps', () => {
    expect(formatDNSCacheTimestamp(1_700_000_000)).toBeTruthy();
  });
});
