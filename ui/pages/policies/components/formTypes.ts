import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView, PolicyCreateRequest } from '../../../types';
import type { PolicyOverlayMode } from '../policyBuilderTypes';

export type UpdateDraft = (mutator: (next: PolicyCreateRequest) => void) => void;
export type SetDraft = Dispatch<SetStateAction<PolicyCreateRequest>>;

export interface PolicyBuilderFormMutations {
  addGroup: () => void;
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
  addRule: (groupIndex: number) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
}

export interface PolicyBuilderFormSharedProps extends PolicyBuilderFormMutations {
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
  draft: PolicyCreateRequest;
  integrations: IntegrationView[];
  setDraft: SetDraft;
  updateDraft: UpdateDraft;
  onDelete: (policyId: string) => void;
}

export interface ScopedSourceGroupEditorProps extends PolicyBuilderFormMutations {
  draft: PolicyCreateRequest;
  integrations: IntegrationView[];
  updateDraft: UpdateDraft;
  overlayMode: PolicyOverlayMode;
  sourceGroupId: string | null;
}
