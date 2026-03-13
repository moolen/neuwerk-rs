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
      className="rounded-xl p-6"
      style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Performance Mode
          </h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Toggle Audit and Wiretap availability across the control plane.
          </p>
          <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
            Source: <strong>{status?.source ?? '-'}</strong>
          </p>
        </div>
        <button
          type="button"
          onClick={() => onToggle(!enabled)}
          disabled={disabled}
          className="px-4 py-2 text-sm font-semibold rounded-lg shadow-sm transition-colors"
          style={{
            minHeight: 40,
            background: enabled ? 'var(--accent)' : 'var(--bg-card)',
            color: enabled ? 'white' : 'var(--text)',
            border: enabled ? 'none' : '1px solid var(--border-glass)',
            cursor: disabled ? 'not-allowed' : 'pointer',
            opacity: disabled ? 0.65 : 1,
          }}
        >
          {saving ? 'Saving...' : enabled ? 'Enabled' : 'Disabled'}
        </button>
      </div>
    </div>
  );
};
