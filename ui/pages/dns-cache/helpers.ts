import type { DNSCacheEntry } from '../../types';

export function filterDNSCacheEntries(entries: DNSCacheEntry[], searchTerm: string): DNSCacheEntry[] {
  const search = searchTerm.toLowerCase();
  return entries.filter(
    (entry) =>
      entry.hostname.toLowerCase().includes(search) ||
      entry.ips.some((ip) => ip.toLowerCase().includes(search))
  );
}

export function formatDNSCacheTimestamp(timestamp: number): string {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp * 1000);
  return date.toLocaleString();
}
