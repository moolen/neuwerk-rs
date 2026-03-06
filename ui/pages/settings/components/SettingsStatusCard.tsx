import React from 'react';
import type { TlsInterceptCaStatus } from '../../../types';

interface SettingsStatusCardProps {
  status: TlsInterceptCaStatus | null;
  loading: boolean;
  onRefresh: () => void;
}

export const SettingsStatusCard: React.FC<SettingsStatusCardProps> = ({ status, loading, onRefresh }) => (
  <div className="rounded-xl p-6" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
        TLS Intercept CA Status
      </h2>
      <button
        onClick={onRefresh}
        className="px-4 py-2 text-sm font-semibold rounded-lg shadow-sm transition-colors"
        style={{
          minHeight: 40,
          background: 'var(--bg-card)',
          color: 'var(--text)',
          border: '1px solid var(--border-glass)',
          cursor: loading ? 'not-allowed' : 'pointer',
        }}
        disabled={loading}
      >
        Refresh
      </button>
    </div>
    {loading ? (
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        Loading...
      </p>
    ) : (
      <div className="text-sm space-y-1" style={{ color: 'var(--text-secondary)' }}>
        <p>
          Configured: <strong>{status?.configured ? 'yes' : 'no'}</strong>
        </p>
        <p>
          Source: <strong>{status?.source || '-'}</strong>
        </p>
        <p>
          Fingerprint: <code>{status?.fingerprint_sha256 || '-'}</code>
        </p>
      </div>
    )}
  </div>
);
