import React from 'react';

import { PageLayout } from '../components/layout/PageLayout';
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
    <PageLayout
      title="Policies"
      description="Form-driven policy builder with live validation."
      actions={<PoliciesPageHeader onRefresh={loadAll} onCreate={handleCreate} />}
    >

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(16rem,20rem)_minmax(0,1fr)] xl:items-start">
        <aside className="xl:sticky xl:top-24">
          <PolicySnapshotsPanel
            loading={loading}
            policies={policies}
            selectedId={selectedId}
            onSelect={(id) => {
              void loadEditorForPolicy(id);
            }}
          />
        </aside>

        <div className="space-y-4">
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
            onDelete={(id) => {
              void handleDelete(id);
            }}
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
    </PageLayout>
  );
};
