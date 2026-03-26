import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView, PolicyCreateRequest, PolicyRecord } from '../../types';

export type PolicyEditorMode = 'create' | 'edit';
export type PolicyOverlayMode = 'closed' | 'create-group' | 'edit-group';

export interface PolicyBuilderLifecycleDeps {
  selectedPolicyId: string | null;
  editorMode: PolicyEditorMode;
  editorTargetId: string | null;
  overlayMode: PolicyOverlayMode;
  overlaySourceGroupId: string | null;
  draft: PolicyCreateRequest;
  integrationNames: Set<string>;
  setPolicies: Dispatch<SetStateAction<PolicyRecord[]>>;
  setIntegrations: Dispatch<SetStateAction<IntegrationView[]>>;
  setSelectedPolicyId: Dispatch<SetStateAction<string | null>>;
  setOverlayMode: Dispatch<SetStateAction<PolicyOverlayMode>>;
  setOverlaySourceGroupId: Dispatch<SetStateAction<string | null>>;
  setLoading: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string | null>>;
  setDraft: Dispatch<SetStateAction<PolicyCreateRequest>>;
  setEditorMode: Dispatch<SetStateAction<PolicyEditorMode>>;
  setEditorTargetId: Dispatch<SetStateAction<string | null>>;
  setSaving: Dispatch<SetStateAction<boolean>>;
  setEditorError: Dispatch<SetStateAction<string | null>>;
}

export interface PolicyBuilderLifecycleHandlers {
  handleCreate: () => void;
  loadEditorForPolicy: (policyId: string) => Promise<void>;
  loadAll: () => Promise<void>;
  handleDelete: (policyId: string) => Promise<void>;
  handleSave: () => Promise<void>;
}
