import React from 'react';
import { Plus, RefreshCw } from 'lucide-react';

interface IntegrationsHeaderProps {
  onRefresh: () => void;
  onCreateNew: () => void;
}

export const IntegrationsHeader: React.FC<IntegrationsHeaderProps> = ({ onRefresh, onCreateNew }) => (
  <div className="flex items-center justify-between">
    <div>
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>
        Integrations
      </h1>
      <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
        Configure external inventory providers used by policy dynamic source selectors.
      </p>
    </div>
    <div className="flex items-center gap-3">
      <button
        onClick={onRefresh}
        className="px-3 py-2 text-sm rounded-lg border"
        style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}
      >
        <span className="flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </span>
      </button>
      <button
        onClick={onCreateNew}
        className="px-4 py-2 text-white rounded-lg flex items-center space-x-2 transition-colors"
        style={{ background: 'var(--accent)' }}
      >
        <Plus className="w-4 h-4" />
        <span>New Integration</span>
      </button>
    </div>
  </div>
);
