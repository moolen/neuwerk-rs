export type ServiceAccountStatus = 'active' | 'disabled';
export type ServiceAccountTokenStatus = 'active' | 'revoked';

export interface ServiceAccount {
  id: string;
  name: string;
  description?: string | null;
  created_at: string;
  created_by: string;
  status: ServiceAccountStatus;
}

export interface ServiceAccountToken {
  id: string;
  service_account_id: string;
  name?: string | null;
  created_at: string;
  created_by: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  last_used_at?: string | null;
  kid: string;
  status: ServiceAccountTokenStatus;
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string | null;
}

export interface CreateServiceAccountTokenRequest {
  name?: string;
  ttl?: string;
  eternal?: boolean;
}

export interface CreateServiceAccountTokenResponse {
  token: string;
  token_meta: ServiceAccountToken;
}
