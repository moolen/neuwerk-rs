import React from 'react';
import type { PerformanceModeStatus } from '../../../types';

interface PerformanceModeCardProps {
  status: PerformanceModeStatus | null;
  loading: boolean;
  saving: boolean;
  onToggle: (enabled: boolean) => void;
}

export const PerformanceModeCard: React.FC<PerformanceModeCardProps> = ({
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
        background: 'linear-gradient(145deg, var(--bg-glass), rgba(14,165,233,0.08))',
        border: '1px solid var(--border-glass)',
        boxShadow: 'var(--shadow-glass)',
      }}
    >
      <div className="flex h-full flex-col gap-5">
        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: enabled ? 'var(--green)' : 'var(--amber)',
              background: enabled ? 'var(--green-bg)' : 'var(--amber-bg)',
              border: enabled ? '1px solid var(--green-border)' : '1px solid var(--amber-border)',
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
            Source: {status?.source ?? '-'}
          </span>
        </div>

        <div className="space-y-2">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Performance Mode
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Toggle Audit and Wiretap availability across the control plane.
          </p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Use this when packet forwarding takes priority and the cluster can tolerate reduced observability surfaces.
          </p>
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
          {saving ? 'Saving...' : enabled ? 'Disable Mode' : 'Enable Mode'}
        </button>
      </div>
    </div>
  );
};
