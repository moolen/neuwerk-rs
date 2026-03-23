import React from 'react';
import { Plus, RefreshCw } from 'lucide-react';

interface PoliciesPageHeaderProps {
  onRefresh: () => void;
  onCreate: () => void;
}

export const PoliciesPageHeader: React.FC<PoliciesPageHeaderProps> = ({ onRefresh, onCreate }) => (
  <div className="flex flex-wrap items-center gap-3">
    <button
      onClick={onRefresh}
      className="px-3 py-2 text-sm rounded-lg border"
      style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }}
    >
      <span className="flex items-center gap-2">
        <RefreshCw className="w-4 h-4" />
        Refresh
      </span>
    </button>
    <button
      onClick={onCreate}
      className="px-4 py-2 text-white rounded-lg flex items-center space-x-2 transition-colors"
      style={{ background: 'var(--accent)' }}
    >
      <Plus className="w-4 h-4" />
      <span>New Policy</span>
    </button>
  </div>
);
