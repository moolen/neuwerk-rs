import React from 'react';
import type { DNSCacheEntry } from '../../../types';
import { formatDNSCacheTimestamp } from '../helpers';

interface DNSCacheTableProps {
  entries: DNSCacheEntry[];
  loading: boolean;
  searchTerm: string;
}

const cardLabelStyle = {
  color: 'var(--text-muted)',
} as const;

export const DNSCacheTable: React.FC<DNSCacheTableProps> = ({ entries, loading, searchTerm }) => (
  <>
    <div className="md:hidden space-y-3">
      {loading ? (
        [1, 2, 3].map((i) => (
          <div
            key={i}
            className="rounded-xl p-4 space-y-3"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div className="h-5 rounded animate-pulse w-32" style={{ background: 'var(--bg-glass-subtle)' }} />
            <div className="h-4 rounded animate-pulse w-full" style={{ background: 'var(--bg-glass-subtle)' }} />
            <div className="h-4 rounded animate-pulse w-28" style={{ background: 'var(--bg-glass-subtle)' }} />
          </div>
        ))
      ) : entries.length === 0 ? (
        <div
          className="rounded-[1.25rem] p-6 text-center space-y-2"
          style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}
        >
          <div className="text-base font-semibold" style={{ color: 'var(--text)' }}>
            No observed DNS mappings yet
          </div>
          <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {searchTerm ? 'No cached hostnames or IPs match this filter. Adjust the search scope or refresh the cache.' : 'Refresh the cache after new DNS activity to populate this view.'}
          </div>
        </div>
      ) : (
        entries.map((entry, index) => (
          <div
            key={`${entry.hostname}-${index}`}
            className="rounded-[1.25rem] p-4 space-y-4"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={cardLabelStyle}>
                  Hostname
                </div>
                <div className="mt-1 text-sm font-semibold" style={{ color: 'var(--text)' }}>
                  {entry.hostname}
                </div>
              </div>
              <span
                className="shrink-0 rounded-full px-2.5 py-1 text-[11px] font-semibold"
                style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}
              >
                {entry.ips.length} IP{entry.ips.length === 1 ? '' : 's'} observed
              </span>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-[0.18em]" style={cardLabelStyle}>
                Resolved IPs
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
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
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-[0.18em]" style={cardLabelStyle}>
                Observed at
              </div>
              <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                {formatDNSCacheTimestamp(entry.last_seen)}
              </div>
            </div>
          </div>
        ))
      )}
    </div>

    <div className="hidden md:block rounded-[1.25rem] overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
      <table className="w-full min-w-[640px]">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Hostname
            </th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Resolved IPs
            </th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              Observed at
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
                <div className="text-base font-semibold" style={{ color: 'var(--text)' }}>
                  No observed DNS mappings yet
                </div>
                <div className="mt-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {searchTerm ? 'No cached hostnames or IPs match this filter. Adjust the search scope or refresh the cache.' : 'Refresh the cache after new DNS activity to populate this view.'}
                </div>
              </td>
            </tr>
          ) : (
            entries.map((entry, index) => (
              <tr
                key={`${entry.hostname}-${index}`}
                style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}
              >
                <td className="py-3 px-4">
                  <div>
                    <div className="font-semibold" style={{ color: 'var(--text)' }}>
                      {entry.hostname}
                    </div>
                    <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                      {entry.ips.length} IP{entry.ips.length === 1 ? '' : 's'} observed
                    </div>
                  </div>
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
  </>
);
