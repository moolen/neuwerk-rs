import React from 'react';
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>DNS Cache</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Hostname to IP mappings observed by the firewall
        </p>
      </div>

      <DNSCacheControls
        searchTerm={searchTerm}
        loading={loading}
        onSearchTermChange={setSearchTerm}
        onRefresh={() => void refresh()}
      />

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {filteredEntries.length} {filteredEntries.length === 1 ? 'entry' : 'entries'}
        {searchTerm && ` (filtered from ${entries.length} total)`}
      </div>

      <DNSCacheTable entries={filteredEntries} loading={loading} searchTerm={searchTerm} />
    </div>
  );
};
