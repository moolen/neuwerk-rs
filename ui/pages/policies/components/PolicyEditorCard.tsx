import React from 'react';

import type { IntegrationView, PolicyCreateRequest } from '../../../types';
import type { PolicyValidationIssue } from '../../../utils/policyValidation';
import { PolicyBuilderForm } from './PolicyBuilderForm';
import { PolicyEditorHeader } from './PolicyEditorHeader';
import { PolicyEditorMessages } from './PolicyEditorMessages';

interface PolicyEditorCardProps {
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  draft: PolicyCreateRequest;
  integrations: IntegrationView[];
  setDraft: React.Dispatch<React.SetStateAction<PolicyCreateRequest>>;
  updateDraft: (mutator: (next: PolicyCreateRequest) => void) => void;
  addGroup: () => void;
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
  addRule: (groupIndex: number) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
  validationIssues: PolicyValidationIssue[];
  editorError: string | null;
  onDelete: (policyId: string) => void;
}

export const PolicyEditorCard: React.FC<PolicyEditorCardProps> = ({
  editorMode,
  editorTargetId,
  draft,
  integrations,
  setDraft,
  updateDraft,
  addGroup,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
  validationIssues,
  editorError,
  onDelete,
}) => (
  <>
    <div
      className="rounded-[1.5rem] overflow-hidden"
      style={{
        background: 'linear-gradient(180deg, var(--bg-glass-strong), rgba(255,255,255,0.04))',
        border: '1px solid var(--border-glass)',
        boxShadow: 'var(--shadow-glass)',
      }}
    >
      <PolicyEditorHeader
        editorMode={editorMode}
        editorTargetId={editorTargetId}
      />

      <PolicyBuilderForm
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
        onDelete={onDelete}
      />
    </div>

    <PolicyEditorMessages validationIssues={validationIssues} editorError={editorError} />
  </>
);
