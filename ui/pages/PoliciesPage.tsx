import React from "react";

import { PageLayout } from "../components/layout/PageLayout";
import type { PolicySourceGroupTelemetry } from "../types";
import { PolicyBasicsSection } from "./policies/components/PolicyBasicsSection";
import { PolicyEditorActions } from "./policies/components/PolicyEditorActions";
import { PolicyEditorMessages } from "./policies/components/PolicyEditorMessages";
import { PolicySourceGroupEditorOverlay } from "./policies/components/PolicySourceGroupEditorOverlay";
import { PolicySourceGroupsTable } from "./policies/components/PolicySourceGroupsTable";
import { ScopedSourceGroupEditor } from "./policies/components/ScopedSourceGroupEditor";
import { loadPolicyTelemetryRemote } from "./policies/policyTelemetryRemote";
import { usePolicyBuilder } from "./policies/usePolicyBuilder";

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
    integrations,
    selectedPolicyId,
    loading,
    error,
    draft,
    editorTargetId,
    overlayMode,
    overlaySourceGroupId,
    saving,
    editorError,
    validationIssues,
  } = state;
  const {
    loadEditorForPolicy,
    openSourceGroupEditor,
    closeSourceGroupEditor,
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

  const selectedSourceGroups = draft.policy.source_groups;
  const overlayOpen = overlayMode !== "closed";
  const activeSourceGroupId = overlayOpen ? overlaySourceGroupId : null;
  const overlaySourceGroupLabel =
    selectedSourceGroups.find(
      (group) => (group.client_key ?? group.id) === overlaySourceGroupId,
    )?.id ??
    overlaySourceGroupId ??
    "source group";

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
        const response = await loadPolicyTelemetryRemote();
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

  const handleOpenSourceGroup = async (groupClientKey: string) => {
    if (selectedPolicyId && editorTargetId !== selectedPolicyId) {
      await loadEditorForPolicy(selectedPolicyId);
    }

    openSourceGroupEditor(groupClientKey);
  };

  const handleCreateSourceGroup = async () => {
    if (!selectedPolicyId) {
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
        description="Form-driven singleton policy editor with live validation."
      >
        {error && (
          <div
            className="rounded-lg p-4"
            style={{
              background: "var(--red-bg)",
              border: "1px solid var(--red-border)",
              color: "var(--red)",
            }}
          >
            {error}
          </div>
        )}

        <div className="space-y-5" data-policies-main-content="true">
          <div
            className="space-y-3 pb-5"
            style={{ borderBottom: "1px solid var(--border-glass)" }}
          >
            <div
              className="text-xs uppercase tracking-[0.24em]"
              style={{ color: "var(--text-muted)" }}
            >
              Policy defaults
            </div>
            <PolicyBasicsSection draft={draft} setDraft={setDraft} />
          </div>

          {loading ? (
            <div
              className="rounded-[1.5rem] px-4 py-6 text-sm"
              style={{
                background: "var(--bg-glass-subtle)",
                border: "1px solid var(--border-glass)",
                color: "var(--text-muted)",
              }}
            >
              Loading policy...
            </div>
          ) : (
            <>
              <PolicySourceGroupsTable
                groups={selectedSourceGroups}
                activeSourceGroupId={activeSourceGroupId}
                telemetryBySourceGroupId={telemetryState.bySourceGroupId}
                telemetryPartial={telemetryState.partial}
                telemetryNodesQueried={telemetryState.nodesQueried}
                telemetryNodesResponded={telemetryState.nodesResponded}
                telemetryNodeErrorCount={telemetryState.nodeErrorCount}
                createActionLabel="Add source group"
                emptyStateDescription="Create the first source group to start organizing traffic under the singleton policy."
                emptyStateTitle="No source groups configured"
                onCreateGroup={() => {
                  void handleCreateSourceGroup();
                }}
                onDeleteGroup={handleDeleteSourceGroup}
                onMoveGroup={handleMoveSourceGroup}
                onSelectGroup={(groupId) => {
                  void handleOpenSourceGroup(groupId);
                }}
              />

              <PolicyEditorActions
                editorTargetId={selectedPolicyId}
                saving={saving}
                validationIssueCount={validationIssues.length}
                onReloadEditor={(policyId) => {
                  void loadEditorForPolicy(policyId);
                }}
                onSave={() => {
                  void handleSave();
                }}
              />

              <PolicyEditorMessages
                validationIssues={validationIssues}
                editorError={editorError}
              />
            </>
          )}
        </div>
      </PageLayout>

      <PolicySourceGroupEditorOverlay
        open={overlayOpen}
        policyLabel="Active policy"
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
