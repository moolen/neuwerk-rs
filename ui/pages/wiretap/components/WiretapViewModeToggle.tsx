import React from 'react';
import type { ViewMode } from '../types';

interface WiretapViewModeToggleProps {
  viewMode: ViewMode;
  onChange: (next: ViewMode) => void;
  disabled?: boolean;
}

export const WiretapViewModeToggle: React.FC<WiretapViewModeToggleProps> = ({
  viewMode,
  onChange,
  disabled = false,
}) => (
  <div
    className="flex items-center gap-2 rounded-lg p-1"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <button
      onClick={() => onChange('live')}
      disabled={disabled}
      className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
      style={{
        ...(viewMode === 'live'
          ? { background: 'var(--accent)', color: 'white' }
          : { color: 'var(--text-muted)' }),
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
      }}
    >
      Live
    </button>
    <button
      onClick={() => onChange('aggregated')}
      disabled={disabled}
      className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
      style={{
        ...(viewMode === 'aggregated'
          ? { background: 'var(--accent)', color: 'white' }
          : { color: 'var(--text-muted)' }),
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
      }}
    >
      Aggregated
    </button>
  </div>
);
