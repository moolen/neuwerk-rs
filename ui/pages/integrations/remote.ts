import {
  createIntegration,
  deleteIntegration,
  getIntegration,
  listIntegrations,
  updateIntegration,
} from '../../services/api';
import type { EditorMode, IntegrationForm } from './types';
import type { IntegrationView } from '../../types';
import type { ValidatedIntegrationInput } from './formValidation';

export function sortIntegrationsByCreatedAt(items: IntegrationView[]): IntegrationView[] {
  return [...items].sort((a, b) => b.created_at.localeCompare(a.created_at));
}

export async function loadIntegrationsRemote(): Promise<IntegrationView[]> {
  const list = await listIntegrations();
  return sortIntegrationsByCreatedAt(list);
}

export async function loadIntegrationRemote(name: string): Promise<IntegrationView> {
  return getIntegration(name);
}

export async function saveIntegrationRemote(
  editorMode: EditorMode,
  selectedName: string | null,
  input: ValidatedIntegrationInput,
  form: IntegrationForm
): Promise<string | null> {
  if (editorMode === 'create') {
    const created = await createIntegration({
      name: input.name,
      kind: form.kind,
      api_server_url: input.apiServerUrl,
      ca_cert_pem: input.caCertPem,
      service_account_token: input.serviceAccountToken,
    });
    return created.name;
  }

  if (selectedName) {
    await updateIntegration(selectedName, {
      api_server_url: input.apiServerUrl,
      ca_cert_pem: input.caCertPem,
      service_account_token: input.serviceAccountToken,
    });
  }

  return null;
}

export async function deleteIntegrationRemote(name: string): Promise<void> {
  await deleteIntegration(name);
}
