import type {
  SsoProviderCreateRequest,
  SsoProviderKind,
  SsoProviderPatchRequest,
  SsoProviderView,
  SsoRole,
} from '../../types';

export interface SsoProviderDraft {
  id?: string;
  name: string;
  kind: SsoProviderKind;
  enabled: boolean;
  display_order: number;
  issuer_url: string;
  authorization_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  subject_claim: string;
  email_claim: string;
  groups_claim: string;
  default_role: SsoRole;
  session_ttl_secs: number;
  admin_subjects: string;
  admin_groups: string;
  admin_email_domains: string;
  readonly_subjects: string;
  readonly_groups: string;
  readonly_email_domains: string;
  allowed_email_domains: string;
}

export function emptySsoProviderDraft(): SsoProviderDraft {
  return {
    name: '',
    kind: 'google',
    enabled: true,
    display_order: 0,
    issuer_url: '',
    authorization_url: '',
    token_url: '',
    userinfo_url: '',
    client_id: '',
    client_secret: '',
    scopes: '',
    subject_claim: 'sub',
    email_claim: 'email',
    groups_claim: '',
    default_role: 'readonly',
    session_ttl_secs: 8 * 60 * 60,
    admin_subjects: '',
    admin_groups: '',
    admin_email_domains: '',
    readonly_subjects: '',
    readonly_groups: '',
    readonly_email_domains: '',
    allowed_email_domains: '',
  };
}

export function ssoDraftFromProvider(provider: SsoProviderView): SsoProviderDraft {
  return {
    id: provider.id,
    name: provider.name,
    kind: provider.kind,
    enabled: provider.enabled,
    display_order: provider.display_order,
    issuer_url: provider.issuer_url ?? '',
    authorization_url: provider.authorization_url ?? '',
    token_url: provider.token_url ?? '',
    userinfo_url: provider.userinfo_url ?? '',
    client_id: provider.client_id,
    client_secret: '',
    scopes: provider.scopes.join(', '),
    subject_claim: provider.subject_claim,
    email_claim: provider.email_claim ?? '',
    groups_claim: provider.groups_claim ?? '',
    default_role: provider.default_role ?? 'readonly',
    session_ttl_secs: provider.session_ttl_secs,
    admin_subjects: provider.admin_subjects.join(', '),
    admin_groups: provider.admin_groups.join(', '),
    admin_email_domains: provider.admin_email_domains.join(', '),
    readonly_subjects: provider.readonly_subjects.join(', '),
    readonly_groups: provider.readonly_groups.join(', '),
    readonly_email_domains: provider.readonly_email_domains.join(', '),
    allowed_email_domains: provider.allowed_email_domains.join(', '),
  };
}

export function validateSsoProviderDraft(draft: SsoProviderDraft): string | null {
  if (!draft.name.trim()) {
    return 'Provider name is required';
  }
  if (!draft.client_id.trim()) {
    return 'Client ID is required';
  }
  if (!draft.id && !draft.client_secret.trim()) {
    return 'Client secret is required for new providers';
  }
  if (draft.kind === 'generic-oidc' && !draft.issuer_url.trim()) {
    return 'Issuer URL is required for generic OIDC providers';
  }
  if (!Number.isFinite(draft.session_ttl_secs) || draft.session_ttl_secs < 1) {
    return 'Session TTL must be >= 1 second';
  }
  return null;
}

export function buildSsoCreateRequest(draft: SsoProviderDraft): SsoProviderCreateRequest {
  return {
    name: draft.name.trim(),
    kind: draft.kind,
    enabled: draft.enabled,
    display_order: draft.display_order,
    issuer_url: optionalText(draft.issuer_url),
    authorization_url: optionalText(draft.authorization_url),
    token_url: optionalText(draft.token_url),
    userinfo_url: optionalText(draft.userinfo_url),
    client_id: draft.client_id.trim(),
    client_secret: optionalText(draft.client_secret),
    scopes: csvToList(draft.scopes),
    subject_claim: optionalText(draft.subject_claim),
    email_claim: optionalText(draft.email_claim),
    groups_claim: optionalText(draft.groups_claim),
    default_role: draft.default_role,
    session_ttl_secs: draft.session_ttl_secs,
    admin_subjects: csvToList(draft.admin_subjects),
    admin_groups: csvToList(draft.admin_groups),
    admin_email_domains: csvToList(draft.admin_email_domains),
    readonly_subjects: csvToList(draft.readonly_subjects),
    readonly_groups: csvToList(draft.readonly_groups),
    readonly_email_domains: csvToList(draft.readonly_email_domains),
    allowed_email_domains: csvToList(draft.allowed_email_domains),
  };
}

export function buildSsoPatchRequest(draft: SsoProviderDraft): SsoProviderPatchRequest {
  const payload: SsoProviderPatchRequest = {
    name: draft.name.trim(),
    enabled: draft.enabled,
    display_order: draft.display_order,
    issuer_url: optionalText(draft.issuer_url),
    authorization_url: optionalText(draft.authorization_url),
    token_url: optionalText(draft.token_url),
    userinfo_url: optionalText(draft.userinfo_url),
    client_id: draft.client_id.trim(),
    scopes: csvToList(draft.scopes),
    subject_claim: optionalText(draft.subject_claim),
    email_claim: optionalText(draft.email_claim),
    groups_claim: optionalText(draft.groups_claim),
    default_role: draft.default_role,
    session_ttl_secs: draft.session_ttl_secs,
    admin_subjects: csvToList(draft.admin_subjects),
    admin_groups: csvToList(draft.admin_groups),
    admin_email_domains: csvToList(draft.admin_email_domains),
    readonly_subjects: csvToList(draft.readonly_subjects),
    readonly_groups: csvToList(draft.readonly_groups),
    readonly_email_domains: csvToList(draft.readonly_email_domains),
    allowed_email_domains: csvToList(draft.allowed_email_domains),
  };

  const secret = optionalText(draft.client_secret);
  if (secret) {
    payload.client_secret = secret;
  }

  return payload;
}

function optionalText(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function csvToList(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}
