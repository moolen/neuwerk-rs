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
    <div
      className="rounded-[1.25rem] p-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
      style={{
        background: 'var(--bg-glass)',
        border: '1px solid var(--border-glass)',
      }}
    >
      <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Review validation feedback before saving changes to the active policy snapshot.
      </div>
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
          className="px-4 py-2 text-sm rounded-xl"
          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
        >
          Revert
        </button>
        <button
          disabled={saveDisabled}
          onClick={onSave}
          className="px-4 py-2 text-sm rounded-xl text-white"
          style={{
            background: saveDisabled ? 'var(--text-muted)' : 'var(--accent)',
            cursor: saveDisabled ? 'not-allowed' : 'pointer',
          }}
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </div>
  );
};
