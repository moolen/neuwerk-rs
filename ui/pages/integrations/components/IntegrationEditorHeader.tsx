import React from 'react';
import { Trash2 } from 'lucide-react';
import type { EditorMode } from '../types';

interface IntegrationEditorHeaderProps {
  editorMode: EditorMode;
  selectedName: string | null;
  onDelete: () => void;
}

export const IntegrationEditorHeader: React.FC<IntegrationEditorHeaderProps> = ({
  editorMode,
  selectedName,
  onDelete,
}) => (
  <div
    className="px-4 py-3 text-sm font-semibold flex items-center justify-between"
    style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
  >
    <div>
      <div>Integration Editor</div>
      <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
        {editorMode === 'create'
          ? 'Create a Kubernetes integration'
          : `Editing ${selectedName ?? 'integration'}`}
      </div>
    </div>
    {editorMode === 'edit' && (
      <button
        onClick={onDelete}
        className="px-3 py-1 text-xs rounded-lg flex items-center gap-1"
        style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
      >
        <Trash2 className="w-3 h-3" />
        Delete
      </button>
    )}
  </div>
);
