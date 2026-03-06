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
  <div className="flex gap-4 items-center">
    <div className="flex-1">
      <input
        type="text"
        placeholder="Search by hostname or IP..."
        value={searchTerm}
        onChange={(e) => onSearchTermChange(e.target.value)}
        className="w-full rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
      />
    </div>

    <button
      onClick={onRefresh}
      disabled={loading}
      className="px-4 py-2 text-white rounded-lg font-medium transition-colors disabled:cursor-not-allowed"
      style={{ background: loading ? 'var(--text-muted)' : 'var(--accent)' }}
    >
      {loading ? 'Loading...' : 'Refresh'}
    </button>
  </div>
);
