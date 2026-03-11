import React from 'react';

import type { SsoProviderView } from '../../../types';
import type { SsoProviderDraft } from '../ssoForm';

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

  return (
    <section className="rounded-xl p-6" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>SSO Providers</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Configure OpenID Connect providers used by the login page.
          </p>
        </div>
        <button
          type="button"
          className="px-3 py-2 rounded-lg text-sm font-semibold"
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

      <div className="grid gap-4 md:grid-cols-[320px_1fr]">
        <div className="rounded-lg p-3" style={{ border: '1px solid var(--border-glass)', background: 'var(--bg-card)' }}>
          {loading && <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading providers...</p>}
          {!loading && providers.length === 0 && (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No SSO providers configured.</p>
          )}
          <div className="space-y-2">
            {providers.map((provider) => (
              <div
                key={provider.id}
                className="p-3 rounded-lg"
                style={{
                  border: provider.id === selectedId ? '1px solid var(--accent)' : '1px solid var(--border-glass)',
                  background: provider.id === selectedId ? 'var(--bg-input)' : 'transparent',
                }}
              >
                <button
                  type="button"
                  className="w-full text-left"
                  onClick={() => onSelect(provider.id)}
                  disabled={disabled}
                >
                  <p className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{provider.name}</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    {provider.kind} {provider.enabled ? 'enabled' : 'disabled'}
                  </p>
                </button>
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    className="px-2 py-1 rounded text-xs"
                    style={{ border: '1px solid var(--border-glass)', color: 'var(--text)' }}
                    onClick={() => onTest(provider.id)}
                    disabled={disabled}
                  >
                    {testingId === provider.id ? 'Testing...' : 'Test'}
                  </button>
                  <button
                    type="button"
                    className="px-2 py-1 rounded text-xs"
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
          className="rounded-lg p-4"
          style={{ border: '1px solid var(--border-glass)', background: 'var(--bg-card)' }}
        >
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
            <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(event) => onDraftChange({ ...draft, enabled: event.target.checked })}
                disabled={disabled}
              />
              Enabled
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
          </div>

          <div className="grid gap-3 mt-3">
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

          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="submit"
              className="px-4 py-2 rounded-lg text-sm font-semibold text-white"
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
