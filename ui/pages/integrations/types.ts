import type { IntegrationKind, IntegrationView } from '../../types';

export type EditorMode = 'create' | 'edit';

export interface IntegrationForm {
  name: string;
  kind: IntegrationKind;
  apiServerUrl: string;
  caCertPem: string;
  serviceAccountToken: string;
}

export function createEmptyIntegrationForm(): IntegrationForm {
  return {
    name: '',
    kind: 'kubernetes',
    apiServerUrl: '',
    caCertPem: '',
    serviceAccountToken: '',
  };
}

export function toIntegrationForm(view: IntegrationView): IntegrationForm {
  return {
    name: view.name,
    kind: 'kubernetes',
    apiServerUrl: view.api_server_url,
    caCertPem: view.ca_cert_pem,
    serviceAccountToken: '',
  };
}
