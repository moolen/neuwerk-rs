import React from 'react';
import type { TlsInterceptCaStatus } from '../../../types';

interface SettingsStatusCardProps {
  status: TlsInterceptCaStatus | null;
  loading: boolean;
  onRefresh: () => void;
}

export const SettingsStatusCard: React.FC<SettingsStatusCardProps> = ({ status, loading, onRefresh }) => (
  <div
    className="rounded-[1.4rem] p-6 h-full"
    style={{
      background: 'var(--bg-glass)',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex items-center justify-between gap-4 mb-4">
      <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
        TLS intercept readiness
      </h2>
      <button
        onClick={onRefresh}
        className="px-4 py-2 text-sm font-semibold rounded-xl shadow-sm transition-colors"
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
      <div className="space-y-4">
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Check whether a usable CA is present before enabling DPI TLS intercept features that depend on cluster trust material.
        </p>
        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: status?.configured ? 'var(--green)' : 'var(--amber)',
              background: status?.configured ? 'var(--green-bg)' : 'var(--amber-bg)',
              border: status?.configured ? '1px solid var(--green-border)' : '1px solid var(--amber-border)',
            }}
          >
            {status?.configured ? 'Configured' : 'Not configured'}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: 'var(--text-secondary)',
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            Source: {status?.source || '-'}
          </span>
        </div>
        <div
          className="rounded-[1rem] p-3"
          style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
        >
          <div className="text-[11px] uppercase tracking-[0.2em]" style={{ color: 'var(--text-muted)' }}>
            Fingerprint
          </div>
          <code className="block mt-2 text-xs break-all" style={{ color: 'var(--text-secondary)' }}>
            {status?.fingerprint_sha256 || '-'}
          </code>
        </div>
      </div>
    )}
  </div>
);
