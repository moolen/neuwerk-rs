import React, { useState, useEffect } from 'react';
import { getDNSCache } from '../services/api';
import type { DNSCacheEntry } from '../types';

export const DNSCachePage: React.FC = () => {
  const [entries, setEntries] = useState<DNSCacheEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchDNSCache = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await getDNSCache();
      const sortedEntries = [...result.entries].sort((a, b) =>
        a.hostname.localeCompare(b.hostname)
      );
      setEntries(sortedEntries);
    } catch (err) {
      console.error('Failed to fetch DNS cache:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch DNS cache');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDNSCache();
  }, []);

  const filteredEntries = entries.filter((entry) => {
    const search = searchTerm.toLowerCase();
    return (
      entry.hostname.toLowerCase().includes(search) ||
      entry.ips.some((ip) => ip.toLowerCase().includes(search))
    );
  });

  const formatTimestamp = (timestamp: number): string => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>DNS Cache</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Hostname to IP mappings observed by the firewall
        </p>
      </div>

      <div className="flex gap-4 items-center">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Search by hostname or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
          />
        </div>

        <button
          onClick={fetchDNSCache}
          disabled={loading}
          className="px-4 py-2 text-white rounded-lg font-medium transition-colors disabled:cursor-not-allowed"
          style={{ background: loading ? 'var(--text-muted)' : 'var(--accent)' }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {filteredEntries.length} {filteredEntries.length === 1 ? 'entry' : 'entries'}
        {searchTerm && ` (filtered from ${entries.length} total)`}
      </div>

      <div className="rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                Hostname
              </th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                IP Addresses
              </th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
                Last Seen
              </th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <>
                {[1, 2, 3, 4, 5].map((i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
                    <td className="py-3 px-4">
                      <div className="h-4 rounded animate-pulse w-48" style={{ background: 'var(--bg-glass)' }} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="h-4 rounded animate-pulse w-32" style={{ background: 'var(--bg-glass)' }} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="h-4 rounded animate-pulse w-40" style={{ background: 'var(--bg-glass)' }} />
                    </td>
                  </tr>
                ))}
              </>
            ) : filteredEntries.length === 0 ? (
              <tr>
                <td colSpan={3} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
                  {searchTerm ? 'No DNS cache entries match your search' : 'No DNS cache entries found'}
                </td>
              </tr>
            ) : (
              filteredEntries.map((entry, index) => (
                <tr
                  key={`${entry.hostname}-${index}`}
                  style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}
                >
                  <td className="py-3 px-4">
                    <span style={{ color: 'var(--text-secondary)' }}>{entry.hostname}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-2">
                      {entry.ips.map((ip) => (
                        <span
                          key={ip}
                          className="font-mono text-xs px-2 py-1 rounded"
                          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                      {formatTimestamp(entry.last_seen)}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
