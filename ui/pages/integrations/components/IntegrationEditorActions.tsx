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
  <div
    className="flex flex-col gap-3 border-t pt-4 sm:flex-row sm:items-center sm:justify-between"
    style={{ borderColor: 'var(--border-glass)' }}
  >
    <p className="text-xs max-w-[34rem]" style={{ color: 'var(--text-muted)' }}>
      {editorMode === 'create'
        ? 'Create a reusable inventory profile for Kubernetes-backed source selectors.'
        : 'Leave the token blank to keep the existing secret while updating the rest of the connection profile.'}
    </p>

    <div className="flex justify-end gap-2">
      <button
        disabled={saving}
        onClick={onReset}
        className="px-4 py-2 text-sm rounded-xl"
        style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
      >
        Reset
      </button>
      <button
        disabled={saving}
        onClick={onSave}
        className="px-4 py-2 text-sm rounded-xl text-white"
        style={{ background: 'var(--accent)' }}
      >
        {saving ? 'Saving...' : editorMode === 'create' ? 'Create Integration' : 'Save Changes'}
      </button>
    </div>
  </div>
);
