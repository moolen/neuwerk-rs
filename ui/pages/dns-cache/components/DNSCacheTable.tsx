import React from 'react';
import type { DNSCacheEntry } from '../../../types';
import { formatDNSCacheTimestamp } from '../helpers';

interface DNSCacheTableProps {
  entries: DNSCacheEntry[];
  loading: boolean;
  searchTerm: string;
}

export const DNSCacheTable: React.FC<DNSCacheTableProps> = ({ entries, loading, searchTerm }) => (
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
        ) : entries.length === 0 ? (
          <tr>
            <td colSpan={3} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
              {searchTerm ? 'No DNS cache entries match your search' : 'No DNS cache entries found'}
            </td>
          </tr>
        ) : (
          entries.map((entry, index) => (
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
                  {formatDNSCacheTimestamp(entry.last_seen)}
                </span>
              </td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  </div>
);
