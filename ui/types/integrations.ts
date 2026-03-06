export type IntegrationKind = 'kubernetes';

export interface IntegrationView {
  id: string;
  created_at: string;
  name: string;
  kind: IntegrationKind;
  api_server_url: string;
  ca_cert_pem: string;
  auth_type: string;
  token_configured: boolean;
}

export interface IntegrationCreateRequest {
  name: string;
  kind: IntegrationKind;
  api_server_url: string;
  ca_cert_pem: string;
  service_account_token: string;
}

export interface IntegrationUpdateRequest {
  api_server_url: string;
  ca_cert_pem: string;
  service_account_token: string;
}
