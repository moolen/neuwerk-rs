import React from 'react';
import type { EditorMode } from '../types';

interface IntegrationEditorActionsProps {
  editorMode: EditorMode;
  saving: boolean;
  onReset: () => void;
  onSave: () => void;
}

export const IntegrationEditorActions: React.FC<IntegrationEditorActionsProps> = ({
  editorMode,
  saving,
  onReset,
  onSave,
}) => (
  <div className="mt-4 flex justify-end gap-2">
    <button
      disabled={saving}
      onClick={onReset}
      className="px-4 py-2 text-sm rounded-lg"
      style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
    >
      Reset
    </button>
    <button
      disabled={saving}
      onClick={onSave}
      className="px-4 py-2 text-sm rounded-lg text-white"
      style={{ background: 'var(--accent)' }}
    >
      {saving ? 'Saving...' : editorMode === 'create' ? 'Create' : 'Update'}
    </button>
  </div>
);
