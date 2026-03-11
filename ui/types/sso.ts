export type SsoProviderKind = 'google' | 'github' | 'generic-oidc';
export type SsoRole = 'admin' | 'readonly';

export interface SsoSupportedProvider {
  id: string;
  name: string;
  kind: SsoProviderKind;
}

export interface SsoProviderView {
  id: string;
  created_at: string;
  updated_at: string;
  name: string;
  kind: SsoProviderKind;
  enabled: boolean;
  display_order: number;
  issuer_url?: string | null;
  authorization_url?: string | null;
  token_url?: string | null;
  userinfo_url?: string | null;
  client_id: string;
  client_secret_configured: boolean;
  scopes: string[];
  pkce_required: boolean;
  subject_claim: string;
  email_claim?: string | null;
  groups_claim?: string | null;
  default_role?: SsoRole | null;
  admin_subjects: string[];
  admin_groups: string[];
  admin_email_domains: string[];
  readonly_subjects: string[];
  readonly_groups: string[];
  readonly_email_domains: string[];
  allowed_email_domains: string[];
  session_ttl_secs: number;
}

export interface SsoProviderCreateRequest {
  name: string;
  kind: SsoProviderKind;
  enabled?: boolean;
  display_order?: number;
  issuer_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  client_id: string;
  client_secret?: string;
  scopes?: string[];
  pkce_required?: boolean;
  subject_claim?: string;
  email_claim?: string;
  groups_claim?: string;
  default_role?: SsoRole;
  admin_subjects?: string[];
  admin_groups?: string[];
  admin_email_domains?: string[];
  readonly_subjects?: string[];
  readonly_groups?: string[];
  readonly_email_domains?: string[];
  allowed_email_domains?: string[];
  session_ttl_secs?: number;
}

export interface SsoProviderPatchRequest {
  name?: string;
  enabled?: boolean;
  display_order?: number;
  issuer_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  pkce_required?: boolean;
  subject_claim?: string;
  email_claim?: string;
  groups_claim?: string;
  default_role?: SsoRole;
  admin_subjects?: string[];
  admin_groups?: string[];
  admin_email_domains?: string[];
  readonly_subjects?: string[];
  readonly_groups?: string[];
  readonly_email_domains?: string[];
  allowed_email_domains?: string[];
  session_ttl_secs?: number;
}

export interface SsoProviderTestResult {
  ok: boolean;
  details: string;
}
