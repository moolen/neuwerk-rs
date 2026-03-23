import React from 'react';

interface DNSCacheControlsProps {
  searchTerm: string;
  loading: boolean;
  onSearchTermChange: (value: string) => void;
  onRefresh: () => void;
}

export const DNSCacheControls: React.FC<DNSCacheControlsProps> = ({
  searchTerm,
  loading,
  onSearchTermChange,
  onRefresh,
}) => (
  <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-end">
    <label className="space-y-2">
      <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
        Lookup filter
      </span>
      <span className="block text-sm" style={{ color: 'var(--text-secondary)' }}>
        Matches hostnames and resolved IP addresses.
      </span>
      <input
        type="text"
        placeholder="Search by hostname or IP..."
        value={searchTerm}
        onChange={(e) => onSearchTermChange(e.target.value)}
        className="w-full rounded-[1rem] px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
        style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
      />
    </label>

    <div className="flex flex-col gap-2 xl:items-end">
      <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Reload the cache after external DNS activity or policy changes.
      </div>
      <button
        onClick={onRefresh}
        disabled={loading}
        className="px-5 py-3 text-white rounded-full font-semibold transition-colors disabled:cursor-not-allowed"
        style={{
          background: loading ? 'var(--text-muted)' : 'linear-gradient(135deg, var(--accent), #3cb7a2)',
          boxShadow: loading ? 'none' : '0 10px 30px rgba(79,110,247,0.25)',
        }}
      >
        {loading ? 'Refreshing…' : 'Refresh cache'}
      </button>
    </div>
  </div>
);
