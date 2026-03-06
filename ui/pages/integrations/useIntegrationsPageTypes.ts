import type { Dispatch, SetStateAction } from 'react';

import type { IntegrationView } from '../../types';
import type { EditorMode, IntegrationForm } from './types';

export interface UseIntegrationsPageState {
  integrations: IntegrationView[];
  selectedName: string | null;
  editorMode: EditorMode;
  form: IntegrationForm;
  loading: boolean;
  saving: boolean;
  error: string | null;
  editorError: string | null;
}

export interface UseIntegrationsPageActions {
  loadIntegrations: () => Promise<void>;
  selectIntegration: (name: string) => Promise<void>;
  createNewIntegration: () => void;
  saveIntegration: () => Promise<void>;
  deleteSelectedIntegration: () => Promise<void>;
  setFormField: (field: keyof IntegrationForm, value: string) => void;
}

export interface IntegrationsPageLifecycleDeps {
  selectedName: string | null;
  editorMode: EditorMode;
  form: IntegrationForm;
  setIntegrations: Dispatch<SetStateAction<IntegrationView[]>>;
  setSelectedName: Dispatch<SetStateAction<string | null>>;
  setEditorMode: Dispatch<SetStateAction<EditorMode>>;
  setForm: Dispatch<SetStateAction<IntegrationForm>>;
  setLoading: Dispatch<SetStateAction<boolean>>;
  setSaving: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string | null>>;
  setEditorError: Dispatch<SetStateAction<string | null>>;
}
