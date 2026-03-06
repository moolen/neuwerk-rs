import { useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView } from '../../types';
import type { EditorMode, IntegrationForm } from './types';
import { createEmptyIntegrationForm } from './types';

export interface IntegrationsPageStateStore {
  integrations: IntegrationView[];
  setIntegrations: Dispatch<SetStateAction<IntegrationView[]>>;
  selectedName: string | null;
  setSelectedName: Dispatch<SetStateAction<string | null>>;
  editorMode: EditorMode;
  setEditorMode: Dispatch<SetStateAction<EditorMode>>;
  form: IntegrationForm;
  setForm: Dispatch<SetStateAction<IntegrationForm>>;
  loading: boolean;
  setLoading: Dispatch<SetStateAction<boolean>>;
  saving: boolean;
  setSaving: Dispatch<SetStateAction<boolean>>;
  error: string | null;
  setError: Dispatch<SetStateAction<string | null>>;
  editorError: string | null;
  setEditorError: Dispatch<SetStateAction<string | null>>;
}

export function useIntegrationsPageState(): IntegrationsPageStateStore {
  const [integrations, setIntegrations] = useState<IntegrationView[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<EditorMode>('create');
  const [form, setForm] = useState<IntegrationForm>(createEmptyIntegrationForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);

  return {
    integrations,
    setIntegrations,
    selectedName,
    setSelectedName,
    editorMode,
    setEditorMode,
    form,
    setForm,
    loading,
    setLoading,
    saving,
    setSaving,
    error,
    setError,
    editorError,
    setEditorError,
  };
}
