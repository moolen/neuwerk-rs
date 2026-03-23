import React from 'react';

import type { SsoProviderView } from '../../../types';
import type { SsoProviderDraft } from '../ssoForm';

function countCsvEntries(value: string): number {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0).length;
}

function renderSummaryPill(label: string, value: string) {
  return (
    <span
      className="px-2.5 py-1 rounded-full text-xs font-semibold"
      style={{
        color: 'var(--text-secondary)',
        background: 'var(--bg-glass-subtle)',
        border: '1px solid var(--border-subtle)',
      }}
    >
      {label}: {value}
    </span>
  );
}

interface SsoProvidersFormProps {
  providers: SsoProviderView[];
  loading: boolean;
  saving: boolean;
  deletingId: string | null;
  testingId: string | null;
  error: string | null;
  success: string | null;
  draft: SsoProviderDraft;
  onSelect: (id: string) => void;
  onCreateNew: () => void;
  onDraftChange: (next: SsoProviderDraft) => void;
  onSave: () => void;
  onDelete: (id: string) => void;
  onTest: (id: string) => void;
}

export const SsoProvidersForm: React.FC<SsoProvidersFormProps> = ({
  providers,
  loading,
  saving,
  deletingId,
  testingId,
  error,
  success,
  draft,
  onSelect,
  onCreateNew,
  onDraftChange,
  onSave,
  onDelete,
  onTest,
}) => {
  const selectedId = draft.id;
  const disabled = saving || Boolean(deletingId) || Boolean(testingId);
  const selectedProvider = providers.find((provider) => provider.id === selectedId);
  const secretConfigured =
    draft.client_secret.trim().length > 0 || Boolean(selectedProvider?.client_secret_configured);
  const adminOverrideCount =
    countCsvEntries(draft.admin_subjects) +
    countCsvEntries(draft.admin_groups) +
    countCsvEntries(draft.admin_email_domains);
  const readonlyOverrideCount =
    countCsvEntries(draft.readonly_subjects) +
    countCsvEntries(draft.readonly_groups) +
    countCsvEntries(draft.readonly_email_domains);
  const allowedDomainCount = countCsvEntries(draft.allowed_email_domains);

  return (
    <section
      className="rounded-[1.5rem] p-6"
      style={{
        background: 'var(--bg-glass)',
        border: '1px solid var(--border-glass)',
        boxShadow: 'var(--shadow-glass)',
      }}
    >
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>Provider directory</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
            Configure OpenID Connect providers, login ordering, and role defaults.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-glass)',
              color: 'var(--text-secondary)',
            }}
          >
            {providers.length} configured
          </div>
          <button
            type="button"
            className="px-3 py-2 rounded-xl text-sm font-semibold"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-glass)',
              color: 'var(--text)',
            }}
            onClick={onCreateNew}
            disabled={disabled}
          >
            New Provider
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
          <p className="text-sm" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      )}

      {success && (
        <div className="mb-4 p-3 rounded-lg" style={{ background: 'var(--green-bg, rgba(34,197,94,0.08))', border: '1px solid var(--green-border, rgba(34,197,94,0.25))' }}>
          <p className="text-sm" style={{ color: 'var(--green, #16a34a)' }}>{success}</p>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(18rem,22rem)_minmax(0,1fr)]">
        <div
          className="rounded-[1.15rem] p-4"
          style={{ border: '1px solid var(--border-glass)', background: 'var(--bg-card)' }}
        >
          <div className="mb-4">
            <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
              Provider list
            </div>
            <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
              Pick an existing provider to edit or create a new login source.
            </div>
          </div>
          {loading && <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading providers...</p>}
          {!loading && providers.length === 0 && (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No SSO providers configured.</p>
          )}
          <div className="space-y-2">
            {providers.map((provider) => (
              <div
                key={provider.id}
                className="p-3 rounded-[1rem]"
                style={{
                  border: provider.id === selectedId ? '1px solid var(--accent)' : '1px solid var(--border-glass)',
                  background: provider.id === selectedId
                    ? 'linear-gradient(145deg, rgba(79,110,247,0.14), rgba(79,110,247,0.05))'
                    : 'transparent',
                }}
              >
                <button
                  type="button"
                  className="w-full text-left"
                  onClick={() => onSelect(provider.id)}
                  disabled={disabled}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{provider.name}</p>
                      <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                        {provider.kind}
                      </p>
                    </div>
                    <span
                      className="px-2 py-1 rounded-full text-[11px] font-semibold"
                      style={{
                        color: provider.enabled ? 'var(--green)' : 'var(--text-secondary)',
                        background: provider.enabled ? 'var(--green-bg)' : 'var(--bg-glass-subtle)',
                        border: provider.enabled ? '1px solid var(--green-border)' : '1px solid var(--border-glass)',
                      }}
                    >
                      {provider.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="mt-3 grid gap-2">
                    <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      Session TTL: {provider.session_ttl_secs}s
                    </div>
                    <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      Secret: {provider.client_secret_configured ? 'configured' : 'missing'}
                    </div>
                  </div>
                </button>
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    className="px-2 py-1 rounded-lg text-xs"
                    style={{ border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    onClick={() => onTest(provider.id)}
                    disabled={disabled}
                  >
                    {testingId === provider.id ? 'Testing...' : 'Test'}
                  </button>
                  <button
                    type="button"
                    className="px-2 py-1 rounded-lg text-xs"
                    style={{ border: '1px solid var(--red-border)', color: 'var(--red)' }}
                    onClick={() => onDelete(provider.id)}
                    disabled={disabled}
                  >
                    {deletingId === provider.id ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            onSave();
          }}
          className="rounded-[1.15rem] p-4 md:p-5"
          style={{ border: '1px solid var(--border-glass)', background: 'var(--bg-card)' }}
        >
          <div className="mb-4">
            <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
              Provider editor
            </div>
            <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
              {draft.id ? `Editing ${draft.name || 'provider'}` : 'Create a new login option'}
            </div>
          </div>

          <div
            className="rounded-[1rem] p-4 mb-4"
            style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
              Editor summary
            </div>
            <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
              Keep core login settings in view and open advanced identity controls only when you need them.
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {renderSummaryPill('Kind', draft.kind)}
              {renderSummaryPill('Default role', draft.default_role)}
              {renderSummaryPill('Status', draft.enabled ? 'enabled' : 'disabled')}
              {renderSummaryPill('Secret', secretConfigured ? 'configured' : 'required')}
            </div>
          </div>

          <div className="space-y-4">
            <section className="rounded-[1rem] p-4" style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}>
              <div className="mb-3">
                <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>Provider basics</div>
                <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                  Name the provider, set ordering, and choose the default role.
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Name
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.name}
                    onChange={(event) => onDraftChange({ ...draft, name: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Kind
                  <select
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.kind}
                    onChange={(event) => onDraftChange({ ...draft, kind: event.target.value as SsoProviderDraft['kind'] })}
                    disabled={disabled}
                  >
                    <option value="google">google</option>
                    <option value="github">github</option>
                    <option value="generic-oidc">generic-oidc</option>
                  </select>
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Default Role
                  <select
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.default_role}
                    onChange={(event) => onDraftChange({ ...draft, default_role: event.target.value as SsoProviderDraft['default_role'] })}
                    disabled={disabled}
                  >
                    <option value="readonly">readonly</option>
                    <option value="admin">admin</option>
                  </select>
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Session TTL (seconds)
                  <input
                    type="number"
                    min={1}
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.session_ttl_secs}
                    onChange={(event) => onDraftChange({ ...draft, session_ttl_secs: Number(event.target.value || '0') })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Display Order
                  <input
                    type="number"
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.display_order}
                    onChange={(event) => onDraftChange({ ...draft, display_order: Number(event.target.value || '0') })}
                    disabled={disabled}
                  />
                </label>
                <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  <input
                    type="checkbox"
                    checked={draft.enabled}
                    onChange={(event) => onDraftChange({ ...draft, enabled: event.target.checked })}
                    disabled={disabled}
                  />
                  Enabled
                </label>
              </div>
            </section>

            <section className="rounded-[1rem] p-4" style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}>
              <div className="mb-3">
                <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>OIDC endpoints and secrets</div>
                <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                  Configure the issuer and all URLs Neuwerk should use during the login flow.
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Client ID
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.client_id}
                    onChange={(event) => onDraftChange({ ...draft, client_id: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Client Secret
                  <input
                    type="password"
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.client_secret}
                    onChange={(event) => onDraftChange({ ...draft, client_secret: event.target.value })}
                    disabled={disabled}
                    placeholder={draft.id ? 'leave blank to keep existing' : ''}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Issuer URL
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.issuer_url}
                    onChange={(event) => onDraftChange({ ...draft, issuer_url: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Authorization URL
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.authorization_url}
                    onChange={(event) => onDraftChange({ ...draft, authorization_url: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Token URL
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.token_url}
                    onChange={(event) => onDraftChange({ ...draft, token_url: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Userinfo URL
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.userinfo_url}
                    onChange={(event) => onDraftChange({ ...draft, userinfo_url: event.target.value })}
                    disabled={disabled}
                  />
                </label>
              </div>
            </section>

            <section className="rounded-[1rem] p-4" style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}>
              <div className="mb-3">
                <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>Scopes and access policy</div>
                <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                  Define requested scopes, global access rules, and role-specific overrides.
                </div>
              </div>
              <div className="grid gap-3">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Scopes (comma-separated)
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.scopes}
                    onChange={(event) => onDraftChange({ ...draft, scopes: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Allowed Email Domains (comma-separated)
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.allowed_email_domains}
                    onChange={(event) => onDraftChange({ ...draft, allowed_email_domains: event.target.value })}
                    disabled={disabled}
                  />
                </label>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                {renderSummaryPill('Allowed domains', String(allowedDomainCount))}
                {renderSummaryPill('Admin overrides', String(adminOverrideCount))}
                {renderSummaryPill('Readonly overrides', String(readonlyOverrideCount))}
              </div>
            </section>

            <details
              className="rounded-[1rem] p-4"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <summary className="cursor-pointer list-none" style={{ color: 'var(--text)' }}>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="text-sm font-semibold">Claim mapping</div>
                    <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                      Adjust how Neuwerk reads subject, email, and group information from the provider.
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {renderSummaryPill('Subject', draft.subject_claim || '-')}
                    {renderSummaryPill('Email', draft.email_claim || '-')}
                    {renderSummaryPill('Groups', draft.groups_claim || '-')}
                  </div>
                </div>
              </summary>

              <div className="grid gap-3 mt-4 sm:grid-cols-3">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Subject Claim
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.subject_claim}
                    onChange={(event) => onDraftChange({ ...draft, subject_claim: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Email Claim
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.email_claim}
                    onChange={(event) => onDraftChange({ ...draft, email_claim: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Groups Claim
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.groups_claim}
                    onChange={(event) => onDraftChange({ ...draft, groups_claim: event.target.value })}
                    disabled={disabled}
                  />
                </label>
              </div>
            </details>

            <details
              className="rounded-[1rem] p-4"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <summary className="cursor-pointer list-none" style={{ color: 'var(--text)' }}>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="text-sm font-semibold">Admin access overrides</div>
                    <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                      Match specific identities, groups, or email domains that should receive admin privileges.
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {renderSummaryPill('Entries', String(adminOverrideCount))}
                  </div>
                </div>
              </summary>

              <div className="grid gap-3 mt-4">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Admin Subjects
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.admin_subjects}
                    onChange={(event) => onDraftChange({ ...draft, admin_subjects: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Admin Groups
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.admin_groups}
                    onChange={(event) => onDraftChange({ ...draft, admin_groups: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Admin Email Domains (comma-separated)
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.admin_email_domains}
                    onChange={(event) => onDraftChange({ ...draft, admin_email_domains: event.target.value })}
                    disabled={disabled}
                  />
                </label>
              </div>
            </details>

            <details
              className="rounded-[1rem] p-4"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <summary className="cursor-pointer list-none" style={{ color: 'var(--text)' }}>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="text-sm font-semibold">Readonly access overrides</div>
                    <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                      Match identities, groups, or domains that should land in readonly sessions.
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {renderSummaryPill('Entries', String(readonlyOverrideCount))}
                  </div>
                </div>
              </summary>

              <div className="grid gap-3 mt-4">
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Readonly Subjects
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.readonly_subjects}
                    onChange={(event) => onDraftChange({ ...draft, readonly_subjects: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Readonly Groups
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.readonly_groups}
                    onChange={(event) => onDraftChange({ ...draft, readonly_groups: event.target.value })}
                    disabled={disabled}
                  />
                </label>
                <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  Readonly Email Domains (comma-separated)
                  <input
                    className="w-full mt-1 p-2 rounded-md text-sm"
                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    value={draft.readonly_email_domains}
                    onChange={(event) => onDraftChange({ ...draft, readonly_email_domains: event.target.value })}
                    disabled={disabled}
                  />
                </label>
              </div>
            </details>
          </div>

          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="submit"
              className="px-4 py-2 rounded-xl text-sm font-semibold text-white"
              style={{ background: 'var(--accent)' }}
              disabled={disabled}
            >
              {saving ? 'Saving...' : draft.id ? 'Save Provider' : 'Create Provider'}
            </button>
          </div>
        </form>
      </div>
    </section>
  );
};
