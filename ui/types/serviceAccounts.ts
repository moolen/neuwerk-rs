export const SERVICE_ACCOUNT_ROLES = ['readonly', 'admin'] as const;

export type ServiceAccountRole = (typeof SERVICE_ACCOUNT_ROLES)[number];
export type ServiceAccountStatus = 'active' | 'disabled';
export type ServiceAccountTokenStatus = 'active' | 'revoked';

export interface ServiceAccount {
  id: string;
  name: string;
  description?: string | null;
  created_at: string;
  created_by: string;
  role: ServiceAccountRole;
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
  role: ServiceAccountRole;
  status: ServiceAccountTokenStatus;
}

export interface CreateServiceAccountRequest {
  name: string;
  description?: string | null;
  role: ServiceAccountRole;
}

export interface UpdateServiceAccountRequest {
  name: string;
  description?: string | null;
  role: ServiceAccountRole;
}

export interface CreateServiceAccountTokenRequest {
  name?: string;
  ttl?: string;
  eternal?: boolean;
  role?: ServiceAccountRole;
}

export interface CreateServiceAccountTokenResponse {
  token: string;
  token_meta: ServiceAccountToken;
}
