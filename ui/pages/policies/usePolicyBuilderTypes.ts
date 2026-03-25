import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView, PolicyCreateRequest, PolicyRecord } from '../../types';
import type { PolicyValidationIssue } from '../../utils/policyValidation';

type PolicyOverlayMode = 'closed' | 'create-group' | 'edit-group';

export interface UsePolicyBuilderState {
  policies: PolicyRecord[];
  integrations: IntegrationView[];
  selectedPolicyId: string | null;
  selectedId: string | null;
  loading: boolean;
  error: string | null;

  draft: PolicyCreateRequest;
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  overlayMode: PolicyOverlayMode;
  overlaySourceGroupId: string | null;
  saving: boolean;
  editorError: string | null;

  validationIssues: PolicyValidationIssue[];
}

export interface UsePolicyBuilderActions {
  loadAll: () => Promise<void>;
  loadEditorForPolicy: (policyId: string) => Promise<void>;
  selectPolicy: (policyId: string) => void;
  openSourceGroupEditor: (sourceGroupId: string | null) => void;
  closeSourceGroupEditor: () => void;
  handleCreate: () => void;
  handleDelete: (policyId: string) => Promise<void>;
  handleSave: () => Promise<void>;

  updateDraft: (mutator: (next: PolicyCreateRequest) => void) => void;
  setDraft: Dispatch<SetStateAction<PolicyCreateRequest>>;
  addGroup: () => void;
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
  addRule: (groupIndex: number) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
}

export interface UsePolicyBuilderResult {
  state: UsePolicyBuilderState;
  actions: UsePolicyBuilderActions;
}
