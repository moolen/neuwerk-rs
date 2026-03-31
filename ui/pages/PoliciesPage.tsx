import React from 'react';

import { PageLayout } from '../components/layout/PageLayout';
import type { PolicySourceGroupTelemetry } from '../types';
import { PoliciesPageHeader } from './policies/components/PoliciesPageHeader';
import { PolicyEditorActions } from './policies/components/PolicyEditorActions';
import { PolicyEditorCard } from './policies/components/PolicyEditorCard';
import { PolicyEditorMessages } from './policies/components/PolicyEditorMessages';
import { PolicySelector } from './policies/components/PolicySelector';
import { PolicySourceGroupEditorOverlay } from './policies/components/PolicySourceGroupEditorOverlay';
import { PolicySourceGroupsTable } from './policies/components/PolicySourceGroupsTable';
import { ScopedSourceGroupEditor } from './policies/components/ScopedSourceGroupEditor';
import { loadPolicyTelemetryRemote } from './policies/policyTelemetryRemote';
import { usePolicyBuilder } from './policies/usePolicyBuilder';

const POLICY_TELEMETRY_REFRESH_MS = 30_000;

export const PoliciesPage: React.FC = () => {
  const { state, actions } = usePolicyBuilder();
  const [telemetryState, setTelemetryState] = React.useState<{
    bySourceGroupId: Record<string, PolicySourceGroupTelemetry>;
    partial: boolean;
    nodesQueried: number;
    nodesResponded: number;
    nodeErrorCount: number;
  }>({
    bySourceGroupId: {},
    partial: false,
    nodesQueried: 0,
    nodesResponded: 0,
    nodeErrorCount: 0,
  });
  const {
    policies,
    integrations,
    selectedPolicyId,
    loading,
    error,
    draft,
    editorMode,
    editorTargetId,
    overlayMode,
    overlaySourceGroupId,
    saving,
    editorError,
    validationIssues,
  } = state;
  const {
    loadAll,
    loadEditorForPolicy,
    openSourceGroupEditor,
    closeSourceGroupEditor,
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

  const selectedPolicy = policies.find((policy) => policy.id === selectedPolicyId) ?? null;
  const selectedPolicyLabel = selectedPolicy?.name?.trim() || selectedPolicy?.id || 'No policy selected';
  const canDeleteSelectedPolicy =
    editorMode === 'edit' &&
    selectedPolicyId !== null &&
    editorTargetId === selectedPolicyId;
  const selectedSourceGroups =
    editorTargetId === selectedPolicyId
      ? draft.policy.source_groups
      : selectedPolicy?.policy.source_groups ?? [];
  const overlayOpen = overlayMode !== 'closed';
  const activeSourceGroupId = overlayOpen ? overlaySourceGroupId : null;
  const showCreatePolicyEditor = editorMode === 'create' && selectedPolicyId === null;
  const overlaySourceGroupLabel =
    selectedSourceGroups.find(
      (group) => (group.client_key ?? group.id) === overlaySourceGroupId,
    )?.id ??
    overlaySourceGroupId ??
    'source group';

  React.useEffect(() => {
    let cancelled = false;
    let intervalId: ReturnType<typeof setInterval> | null = null;

    if (!selectedPolicyId) {
      setTelemetryState({
        bySourceGroupId: {},
        partial: false,
        nodesQueried: 0,
        nodesResponded: 0,
        nodeErrorCount: 0,
      });
      return () => {
        cancelled = true;
      };
    }

    const refreshTelemetry = async () => {
      try {
        const response = await loadPolicyTelemetryRemote(selectedPolicyId);
        if (cancelled) {
          return;
        }
        setTelemetryState({
          bySourceGroupId: Object.fromEntries(
            response.items.map((item) => [item.source_group_id, item]),
          ),
          partial: response.partial,
          nodesQueried: response.nodes_queried,
          nodesResponded: response.nodes_responded,
          nodeErrorCount: response.node_errors.length,
        });
      } catch {
        if (!cancelled) {
          setTelemetryState({
            bySourceGroupId: {},
            partial: false,
            nodesQueried: 0,
            nodesResponded: 0,
            nodeErrorCount: 0,
          });
        }
      }
    };

    void refreshTelemetry();
    intervalId = setInterval(() => {
      void refreshTelemetry();
    }, POLICY_TELEMETRY_REFRESH_MS);

    return () => {
      cancelled = true;
      if (intervalId !== null) {
        clearInterval(intervalId);
      }
    };
  }, [selectedPolicyId]);

  const handleSelectPolicy = (policyId: string) => {
    void loadEditorForPolicy(policyId);
  };

  const handleOpenSourceGroup = async (groupClientKey: string) => {
    if (selectedPolicyId && editorTargetId !== selectedPolicyId) {
      await loadEditorForPolicy(selectedPolicyId);
    }

    openSourceGroupEditor(groupClientKey);
  };

  const handleCreateSourceGroup = async () => {
    if (!selectedPolicyId) {
      handleCreate();
      return;
    }

    if (editorTargetId !== selectedPolicyId) {
      await loadEditorForPolicy(selectedPolicyId);
    }

    addGroup();
    openSourceGroupEditor(null);
  };

  const handleMoveSourceGroup = (groupClientKey: string, direction: -1 | 1) => {
    if (editorTargetId !== selectedPolicyId) return;
    const groupIndex = draft.policy.source_groups.findIndex(
      (group) => (group.client_key ?? group.id) === groupClientKey,
    );
    if (groupIndex < 0) return;
    moveGroup(groupIndex, direction);
  };

  const handleDeleteSourceGroup = (groupClientKey: string) => {
    if (editorTargetId !== selectedPolicyId) return;
    const groupIndex = draft.policy.source_groups.findIndex(
      (group) => (group.client_key ?? group.id) === groupClientKey,
    );
    if (groupIndex < 0) return;
    deleteGroup(groupIndex);
    if (overlaySourceGroupId === groupClientKey) {
      closeSourceGroupEditor();
    }
  };

  return (
    <div className="relative min-h-full" data-policies-page-root="true">
      <PageLayout
        title="Policies"
        description="Form-driven policy builder with live validation."
        actions={
          <PoliciesPageHeader
            onRefresh={loadAll}
            onCreate={handleCreate}
            onDelete={
              canDeleteSelectedPolicy
                ? () => {
                    void handleDelete(selectedPolicyId);
                  }
                : undefined
            }
          />
        }
      >
        {error && (
          <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
            {error}
          </div>
        )}

        <div className="space-y-5" data-policies-main-content="true">
        {showCreatePolicyEditor ? (
          <>
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
              onDelete={(policyId) => {
                void handleDelete(policyId);
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
              onSave={() => {
                void handleSave();
              }}
            />
          </>
        ) : (
          <>
            <PolicySelector
              policies={policies}
              selectedPolicyId={selectedPolicyId}
              onSelect={handleSelectPolicy}
            />

            {loading ? (
              <div
                className="rounded-[1.5rem] px-4 py-6 text-sm"
                style={{
                  background: 'var(--bg-glass-subtle)',
                  border: '1px solid var(--border-glass)',
                  color: 'var(--text-muted)',
                }}
              >
                Loading policies...
              </div>
            ) : (
              <PolicySourceGroupsTable
                groups={selectedSourceGroups}
                activeSourceGroupId={activeSourceGroupId}
                telemetryBySourceGroupId={telemetryState.bySourceGroupId}
                telemetryPartial={telemetryState.partial}
                telemetryNodesQueried={telemetryState.nodesQueried}
                telemetryNodesResponded={telemetryState.nodesResponded}
                telemetryNodeErrorCount={telemetryState.nodeErrorCount}
                createActionLabel={selectedPolicyId ? 'Add source group' : 'Create first policy'}
                emptyStateDescription={
                  selectedPolicyId
                    ? 'Create the first source group to start shaping the selected policy.'
                    : 'Create a policy first, then start organizing traffic by source group.'
                }
                emptyStateTitle={
                  selectedPolicyId ? 'No source groups configured' : 'No policy selected'
                }
                onCreateGroup={() => {
                  void handleCreateSourceGroup();
                }}
                onDeleteGroup={handleDeleteSourceGroup}
                onMoveGroup={handleMoveSourceGroup}
                onSelectGroup={(groupId) => {
                  void handleOpenSourceGroup(groupId);
                }}
              />
            )}
          </>
        )}

        </div>
      </PageLayout>

      <PolicySourceGroupEditorOverlay
        open={overlayOpen}
        policyLabel={selectedPolicyLabel}
        sourceGroupLabel={overlaySourceGroupLabel}
        saving={saving}
        validationIssueCount={validationIssues.length}
        onClose={closeSourceGroupEditor}
        onSave={() => {
          void handleSave();
        }}
      >
        <ScopedSourceGroupEditor
          draft={draft}
          integrations={integrations}
          updateDraft={updateDraft}
          overlayMode={overlayMode}
          sourceGroupId={overlaySourceGroupId}
          duplicateGroup={duplicateGroup}
          moveGroup={moveGroup}
          deleteGroup={deleteGroup}
          addRule={addRule}
          duplicateRule={duplicateRule}
          moveRule={moveRule}
          deleteRule={deleteRule}
        />

        <div className="mt-4">
          <PolicyEditorMessages
            validationIssues={validationIssues}
            editorError={editorError}
          />
        </div>
      </PolicySourceGroupEditorOverlay>
    </div>
  );
};
