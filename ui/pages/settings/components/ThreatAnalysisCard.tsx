import React from 'react';

import type { ThreatIntelSettingsStatus } from '../../../types';

interface ThreatAnalysisCardProps {
  status: ThreatIntelSettingsStatus | null;
  loading: boolean;
  saving: boolean;
  onToggle: (enabled: boolean) => void;
}

export const ThreatAnalysisCard: React.FC<ThreatAnalysisCardProps> = ({
  status,
  loading,
  saving,
  onToggle,
}) => {
  const enabled = status?.enabled ?? true;
  const disabled = loading || saving;

  return (
    <div
      className="rounded-[1.4rem] p-6 h-full"
      style={{
        background: 'linear-gradient(145deg, var(--bg-glass), rgba(79,110,247,0.08))',
        border: '1px solid var(--border-glass)',
        boxShadow: 'var(--shadow-glass)',
      }}
    >
      <div className="flex h-full flex-col gap-5">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={{
                color: enabled ? 'var(--green)' : 'var(--red)',
                background: enabled ? 'var(--green-bg)' : 'var(--red-bg)',
                border: enabled
                  ? '1px solid var(--green-border)'
                  : '1px solid var(--red-border)',
              }}
            >
              {enabled ? 'Enabled' : 'Disabled'}
            </span>
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={{
                color: 'var(--text-secondary)',
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              Alert threshold: {status?.alert_threshold ?? '-'}
            </span>
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={{
                color: 'var(--text-secondary)',
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              Remote enrichment: {status?.remote_enrichment.enabled ? 'On' : 'Off'}
            </span>
          </div>

          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Threat Analysis
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Cluster-wide control for URL, IP, and hostname threat processing.
          </p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            When disabled, new URLs and IPs are not processed and persisted findings stay hidden
            until you re-enable the feature.
          </p>
          <div className="flex flex-wrap gap-2">
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={{
                color: 'var(--text-secondary)',
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              Source: {status?.source ?? '-'}
            </span>
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={{
                color: 'var(--text-secondary)',
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              Baseline feeds: {Object.values(status?.baseline_feeds ?? {}).filter((feed) => feed.enabled).length}
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => onToggle(!enabled)}
          disabled={disabled}
          className="mt-auto px-4 py-2 text-sm font-semibold rounded-xl shadow-sm transition-colors self-start"
          style={{
            minHeight: 40,
            background: enabled ? 'var(--accent)' : 'var(--bg-card)',
            color: enabled ? 'white' : 'var(--text)',
            border: enabled ? 'none' : '1px solid var(--border-glass)',
            cursor: disabled ? 'not-allowed' : 'pointer',
            opacity: disabled ? 0.65 : 1,
          }}
        >
          {saving ? 'Saving...' : enabled ? 'Disable Analysis' : 'Enable Analysis'}
        </button>
      </div>
    </div>
  );
};
