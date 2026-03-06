import React from 'react';

import { PoliciesPageHeader } from './policies/components/PoliciesPageHeader';
import { PolicyEditorActions } from './policies/components/PolicyEditorActions';
import { PolicyEditorCard } from './policies/components/PolicyEditorCard';
import { PolicySnapshotsPanel } from './policies/components/PolicySnapshotsPanel';
import { usePolicyBuilder } from './policies/usePolicyBuilder';

export const PoliciesPage: React.FC = () => {
  const { state, actions } = usePolicyBuilder();
  const {
    policies,
    integrations,
    selectedId,
    loading,
    error,
    draft,
    editorMode,
    editorTargetId,
    saving,
    editorError,
    validationIssues,
  } = state;
  const {
    loadAll,
    loadEditorForPolicy,
    handleCreate,
    handleDelete,
    handleSave,
    updateDraft,
    setDraft,
    addGroup,
    duplicateGroup,
    moveGroup,
    deleteGroup,
    addRule,
    duplicateRule,
    moveRule,
    deleteRule,
  } = actions;

  return (
    <div className="space-y-6">
      <PoliciesPageHeader onRefresh={loadAll} onCreate={handleCreate} />

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1">
          <PolicySnapshotsPanel
            loading={loading}
            policies={policies}
            selectedId={selectedId}
            onSelect={(id) => {
              void loadEditorForPolicy(id);
            }}
            onDelete={(id) => {
              void handleDelete(id);
            }}
          />
        </div>

        <div className="xl:col-span-2 space-y-4">
          <PolicyEditorCard
            editorMode={editorMode}
            editorTargetId={editorTargetId}
            draft={draft}
            integrations={integrations}
            setDraft={setDraft}
            updateDraft={updateDraft}
            addGroup={addGroup}
            duplicateGroup={duplicateGroup}
            moveGroup={moveGroup}
            deleteGroup={deleteGroup}
            addRule={addRule}
            duplicateRule={duplicateRule}
            moveRule={moveRule}
            deleteRule={deleteRule}
            validationIssues={validationIssues}
            editorError={editorError}
          />

          <PolicyEditorActions
            editorMode={editorMode}
            editorTargetId={editorTargetId}
            saving={saving}
            validationIssueCount={validationIssues.length}
            onReloadEditor={(policyId) => {
              void loadEditorForPolicy(policyId);
            }}
            onCreate={handleCreate}
            onSave={handleSave}
          />
        </div>
      </div>
    </div>
  );
};
