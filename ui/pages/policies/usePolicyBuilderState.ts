import { useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView, PolicyCreateRequest, PolicyRecord } from '../../types';
import { createEmptyPolicyRequest } from '../../utils/policyModel';
import type { PolicyEditorMode } from './policyBuilderTypes';

export interface PolicyBuilderStateStore {
  policies: PolicyRecord[];
  setPolicies: Dispatch<SetStateAction<PolicyRecord[]>>;
  integrations: IntegrationView[];
  setIntegrations: Dispatch<SetStateAction<IntegrationView[]>>;
  selectedId: string | null;
  setSelectedId: Dispatch<SetStateAction<string | null>>;
  loading: boolean;
  setLoading: Dispatch<SetStateAction<boolean>>;
  error: string | null;
  setError: Dispatch<SetStateAction<string | null>>;

  draft: PolicyCreateRequest;
  setDraft: Dispatch<SetStateAction<PolicyCreateRequest>>;
  editorMode: PolicyEditorMode;
  setEditorMode: Dispatch<SetStateAction<PolicyEditorMode>>;
  editorTargetId: string | null;
  setEditorTargetId: Dispatch<SetStateAction<string | null>>;
  saving: boolean;
  setSaving: Dispatch<SetStateAction<boolean>>;
  editorError: string | null;
  setEditorError: Dispatch<SetStateAction<string | null>>;
}

export function usePolicyBuilderState(): PolicyBuilderStateStore {
  const [policies, setPolicies] = useState<PolicyRecord[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [draft, setDraft] = useState<PolicyCreateRequest>(createEmptyPolicyRequest());
  const [editorMode, setEditorMode] = useState<PolicyEditorMode>('create');
  const [editorTargetId, setEditorTargetId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);

  return {
    policies,
    setPolicies,
    integrations,
    setIntegrations,
    selectedId,
    setSelectedId,
    loading,
    setLoading,
    error,
    setError,
    draft,
    setDraft,
    editorMode,
    setEditorMode,
    editorTargetId,
    setEditorTargetId,
    saving,
    setSaving,
    editorError,
    setEditorError,
  };
}
