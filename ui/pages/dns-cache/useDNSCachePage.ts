import { useEffect, useMemo, useState } from 'react';
import { getDNSCache } from '../../services/api';
import type { DNSCacheEntry } from '../../types';
import { filterDNSCacheEntries } from './helpers';

export function useDNSCachePage() {
  const [entries, setEntries] = useState<DNSCacheEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const refresh = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await getDNSCache();
      const sortedEntries = [...result.entries].sort((a, b) => a.hostname.localeCompare(b.hostname));
      setEntries(sortedEntries);
    } catch (err) {
      console.error('Failed to fetch DNS cache:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch DNS cache');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const filteredEntries = useMemo(
    () => filterDNSCacheEntries(entries, searchTerm),
    [entries, searchTerm]
  );

  return {
    entries,
    filteredEntries,
    loading,
    error,
    searchTerm,
    setSearchTerm,
    refresh,
  };
}
