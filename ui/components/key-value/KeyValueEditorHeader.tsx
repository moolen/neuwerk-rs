import React from 'react';
import { Plus } from 'lucide-react';

interface KeyValueEditorHeaderProps {
  label: string;
  disabled: boolean;
  onAddEntry: () => void;
}

export const KeyValueEditorHeader: React.FC<KeyValueEditorHeaderProps> = ({
  label,
  disabled,
  onAddEntry,
}) => (
  <div className="flex items-center justify-between mb-2">
    <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
      {label}
    </label>
    <button
      type="button"
      onClick={onAddEntry}
      disabled={disabled}
      className="px-2 py-1 rounded text-xs flex items-center gap-1"
      style={{
        background: 'var(--bg-glass-subtle)',
        color: 'var(--text-secondary)',
        border: '1px solid var(--border-subtle)',
      }}
    >
      <Plus className="w-3 h-3" /> Add
    </button>
  </div>
);
