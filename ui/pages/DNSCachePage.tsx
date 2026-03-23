import React from 'react';
import { PageLayout } from '../components/layout/PageLayout';
import { DNSCacheControls } from './dns-cache/components/DNSCacheControls';
import { DNSCacheTable } from './dns-cache/components/DNSCacheTable';
import { useDNSCachePage } from './dns-cache/useDNSCachePage';

export const DNSCachePage: React.FC = () => {
  const {
    entries,
    filteredEntries,
    loading,
    error,
    searchTerm,
    setSearchTerm,
    refresh,
  } = useDNSCachePage();

  const visibleIpCount = filteredEntries.reduce((total, entry) => total + entry.ips.length, 0);
  const totalIpCount = entries.reduce((total, entry) => total + entry.ips.length, 0);
  const trimmedSearchTerm = searchTerm.trim();
  const summaryCards = [
    {
      label: 'Visible hostnames',
      value: `${filteredEntries.length} ${filteredEntries.length === 1 ? 'hostname' : 'hostnames'}`,
      detail:
        filteredEntries.length === entries.length
          ? 'Current cache view'
          : `Filtered from ${entries.length} cached hostnames`,
    },
    {
      label: 'Resolved IPs',
      value: `${visibleIpCount} resolved IP${visibleIpCount === 1 ? '' : 's'}`,
      detail:
        visibleIpCount === totalIpCount
          ? 'Addresses linked to the visible cache set'
          : `Filtered from ${totalIpCount} cached IPs`,
    },
    {
      label: 'Search scope',
      value: trimmedSearchTerm ? 'Filtered view' : 'Full cache',
      detail: trimmedSearchTerm ? `Matching "${trimmedSearchTerm}"` : 'No hostname or IP filter applied',
    },
  ];

  return (
    <PageLayout
      title="DNS Cache"
      description="Hostname to IP mappings observed by Neuwerk"
    >
      <section
        className="rounded-[1.5rem] p-5 space-y-4"
        style={{
          background: 'var(--bg-glass)',
          border: '1px solid var(--border-glass)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
              Cache posture
            </div>
            <h2 className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
              DNS mappings at a glance
            </h2>
            <p className="mt-1 text-sm max-w-[44rem]" style={{ color: 'var(--text-secondary)' }}>
              Use the current host and IP counts to understand how much cached resolution data is visible before drilling into individual mappings.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)', color: 'var(--text-secondary)' }}
          >
            Refresh on demand
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          {summaryCards.map((card) => (
            <div
              key={card.label}
              className="rounded-[1.15rem] p-4"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                {card.label}
              </div>
              <div className="mt-2 text-2xl font-bold" style={{ color: 'var(--text)' }}>
                {card.value}
              </div>
              <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                {card.detail}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section
        className="rounded-[1.5rem] p-5 space-y-5"
        style={{
          background: 'linear-gradient(135deg, var(--bg-glass-strong), var(--bg-glass-subtle))',
          border: '1px solid var(--border-glass)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
              Search and refresh
            </div>
            <h2 className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
              Filter cached mappings quickly
            </h2>
            <p className="mt-1 text-sm max-w-[44rem]" style={{ color: 'var(--text-secondary)' }}>
              Search across hostnames and resolved IPs, then manually refresh when you need a fresh view from the cluster.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text-secondary)' }}
          >
            Manual operator controls
          </div>
        </div>

        <DNSCacheControls
          searchTerm={searchTerm}
          loading={loading}
          onSearchTermChange={setSearchTerm}
          onRefresh={() => void refresh()}
        />
      </section>

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <section
        className="rounded-[1.5rem] p-5 space-y-5"
        style={{
          background: 'var(--bg-glass)',
          border: '1px solid var(--border-glass)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
              Observed mappings
            </div>
            <h2 className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
              Review hostname-to-IP resolutions
            </h2>
            <p className="mt-1 text-sm max-w-[44rem]" style={{ color: 'var(--text-secondary)' }}>
              Scan the cached resolution set in hostname order, compare resolved IPs, and use the last-observed timestamp to judge recency.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)', color: 'var(--text-secondary)' }}
          >
            {loading ? 'Refreshing cache…' : `${filteredEntries.length} ${filteredEntries.length === 1 ? 'mapping' : 'mappings'} visible`}
          </div>
        </div>

        <DNSCacheTable entries={filteredEntries} loading={loading} searchTerm={searchTerm} />
      </section>
    </PageLayout>
  );
};
