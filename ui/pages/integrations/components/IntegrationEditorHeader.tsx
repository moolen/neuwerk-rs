import React from 'react';
import { Trash2 } from 'lucide-react';
import type { EditorMode } from '../types';

interface IntegrationEditorHeaderProps {
  editorMode: EditorMode;
  selectedName: string | null;
  kind: string;
  tokenConfigured: boolean;
  onDelete: () => void;
}

export const IntegrationEditorHeader: React.FC<IntegrationEditorHeaderProps> = ({
  editorMode,
  selectedName,
  onDelete,
}) => (
  <div
    className="px-5 py-4"
    style={{ borderBottom: '1px solid var(--border-glass)' }}
  >
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <div>
          <div className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            {editorMode === 'create' ? 'New integration draft' : selectedName ?? 'Integration editor'}
          </div>
          <div className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            {editorMode === 'create'
              ? 'Define the cluster endpoint and credentials for a new inventory source.'
              : `Editing ${selectedName ?? 'integration'} for policy-driven dynamic source resolution.`}
          </div>
        </div>
      </div>

      {editorMode === 'edit' && (
        <button
          onClick={onDelete}
          className="px-3 py-2 text-xs rounded-xl flex items-center gap-1 self-start"
          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
        >
          <Trash2 className="w-3 h-3" />
          Delete
        </button>
      )}
    </div>
  </div>
);
