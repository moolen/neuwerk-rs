import React from 'react';

import { isPolicySaveDisabled } from './policiesPageHelpers';

interface PolicyEditorActionsProps {
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  saving: boolean;
  validationIssueCount: number;
  onReloadEditor: (policyId: string) => void;
  onCreate: () => void;
  onSave: () => void;
}

export const PolicyEditorActions: React.FC<PolicyEditorActionsProps> = ({
  editorMode,
  editorTargetId,
  saving,
  validationIssueCount,
  onReloadEditor,
  onCreate,
  onSave,
}) => {
  const saveDisabled = isPolicySaveDisabled(saving, validationIssueCount);
  return (
    <div className="flex justify-end gap-2">
      <button
        disabled={saving}
        onClick={() => {
          if (editorMode === 'edit' && editorTargetId) {
            onReloadEditor(editorTargetId);
          } else {
            onCreate();
          }
        }}
        className="px-4 py-2 text-sm rounded-lg"
        style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
      >
        Revert
      </button>
      <button
        disabled={saveDisabled}
        onClick={onSave}
        className="px-4 py-2 text-sm rounded-lg text-white"
        style={{
          background: saveDisabled ? 'var(--text-muted)' : 'var(--accent)',
          cursor: saveDisabled ? 'not-allowed' : 'pointer',
        }}
      >
        {saving ? 'Saving...' : 'Save'}
      </button>
    </div>
  );
};
