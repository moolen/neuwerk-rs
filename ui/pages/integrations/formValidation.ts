import type { EditorMode, IntegrationForm } from './types';

export interface ValidatedIntegrationInput {
  name: string;
  apiServerUrl: string;
  caCertPem: string;
  serviceAccountToken: string;
}

export function validateIntegrationFormForSave(
  form: IntegrationForm,
  editorMode: EditorMode
): { value?: ValidatedIntegrationInput; error?: string } {
  const name = form.name.trim();
  const apiServerUrl = form.apiServerUrl.trim();
  const caCertPem = form.caCertPem.trim();
  const serviceAccountToken = form.serviceAccountToken.trim();

  if (editorMode === 'create' && !name) {
    return { error: 'name is required' };
  }
  if (!apiServerUrl) {
    return { error: 'kube-apiserver URL is required' };
  }
  if (!caCertPem) {
    return { error: 'kube-apiserver CA certificate is required' };
  }
  if (!serviceAccountToken) {
    return { error: 'service account token is required' };
  }

  return {
    value: {
      name,
      apiServerUrl,
      caCertPem,
      serviceAccountToken,
    },
  };
}
