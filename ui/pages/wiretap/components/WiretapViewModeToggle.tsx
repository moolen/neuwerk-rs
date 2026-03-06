import React from 'react';
import type { ViewMode } from '../types';

interface WiretapViewModeToggleProps {
  viewMode: ViewMode;
  onChange: (next: ViewMode) => void;
}

export const WiretapViewModeToggle: React.FC<WiretapViewModeToggleProps> = ({
  viewMode,
  onChange,
}) => (
  <div
    className="flex items-center gap-2 rounded-lg p-1"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <button
      onClick={() => onChange('live')}
      className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
      style={viewMode === 'live' ? { background: 'var(--accent)', color: 'white' } : { color: 'var(--text-muted)' }}
    >
      Live
    </button>
    <button
      onClick={() => onChange('aggregated')}
      className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
      style={
        viewMode === 'aggregated'
          ? { background: 'var(--accent)', color: 'white' }
          : { color: 'var(--text-muted)' }
      }
    >
      Aggregated
    </button>
  </div>
);
