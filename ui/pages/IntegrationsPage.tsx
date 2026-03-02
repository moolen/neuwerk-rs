import React, { useEffect, useState } from 'react';
import { Plus, RefreshCw, Trash2 } from 'lucide-react';
import {
  createIntegration,
  deleteIntegration,
  getIntegration,
  listIntegrations,
  updateIntegration,
} from '../services/api';
import type { IntegrationKind, IntegrationView } from '../types';

type EditorMode = 'create' | 'edit';

interface IntegrationForm {
  name: string;
  kind: IntegrationKind;
  apiServerUrl: string;
  caCertPem: string;
  serviceAccountToken: string;
}

const emptyForm = (): IntegrationForm => ({
  name: '',
  kind: 'kubernetes',
  apiServerUrl: '',
  caCertPem: '',
  serviceAccountToken: '',
});

export const IntegrationsPage: React.FC = () => {
  const [integrations, setIntegrations] = useState<IntegrationView[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<EditorMode>('create');
  const [form, setForm] = useState<IntegrationForm>(emptyForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);

  useEffect(() => {
    loadIntegrations();
  }, []);

  const loadIntegrations = async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await listIntegrations();
      const sorted = [...list].sort((a, b) => b.created_at.localeCompare(a.created_at));
      setIntegrations(sorted);
      if (selectedName) {
        const stillExists = sorted.some((item) => item.name === selectedName);
        if (stillExists) {
          return;
        }
      }
      if (sorted.length > 0) {
        await handleSelect(sorted[0].name);
      } else {
        handleCreateNew();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load integrations');
    } finally {
      setLoading(false);
    }
  };

  const fillFormFromIntegration = (view: IntegrationView) => {
    setForm({
      name: view.name,
      kind: 'kubernetes',
      apiServerUrl: view.api_server_url,
      caCertPem: view.ca_cert_pem,
      serviceAccountToken: '',
    });
  };

  const handleSelect = async (name: string) => {
    try {
      setEditorError(null);
      const view = await getIntegration(name);
      setSelectedName(view.name);
      setEditorMode('edit');
      fillFormFromIntegration(view);
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to load integration');
    }
  };

  const handleCreateNew = () => {
    setEditorMode('create');
    setSelectedName(null);
    setForm(emptyForm());
    setEditorError(null);
  };

  const handleSave = async () => {
    const name = form.name.trim();
    const apiServerUrl = form.apiServerUrl.trim();
    const caCertPem = form.caCertPem.trim();
    const serviceAccountToken = form.serviceAccountToken.trim();

    if (editorMode === 'create' && !name) {
      setEditorError('name is required');
      return;
    }
    if (!apiServerUrl) {
      setEditorError('kube-apiserver URL is required');
      return;
    }
    if (!caCertPem) {
      setEditorError('kube-apiserver CA certificate is required');
      return;
    }
    if (!serviceAccountToken) {
      setEditorError('service account token is required');
      return;
    }

    try {
      setSaving(true);
      setEditorError(null);
      let createdName: string | null = null;
      if (editorMode === 'create') {
        const created = await createIntegration({
          name,
          kind: 'kubernetes',
          api_server_url: apiServerUrl,
          ca_cert_pem: caCertPem,
          service_account_token: serviceAccountToken,
        });
        createdName = created.name;
      } else if (selectedName) {
        await updateIntegration(selectedName, {
          api_server_url: apiServerUrl,
          ca_cert_pem: caCertPem,
          service_account_token: serviceAccountToken,
        });
      }
      await loadIntegrations();
      if (editorMode === 'create' && createdName) {
        await handleSelect(createdName);
      }
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to save integration');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!selectedName) return;
    const confirmed = window.confirm(`Delete integration "${selectedName}"?`);
    if (!confirmed) return;
    try {
      await deleteIntegration(selectedName);
      await loadIntegrations();
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to delete integration');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>
            Integrations
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Configure external inventory providers used by policy dynamic source selectors.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadIntegrations}
            className="px-3 py-2 text-sm rounded-lg border"
            style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}
          >
            <span className="flex items-center gap-2">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </span>
          </button>
          <button
            onClick={handleCreateNew}
            className="px-4 py-2 text-white rounded-lg flex items-center space-x-2 transition-colors"
            style={{ background: 'var(--accent)' }}
          >
            <Plus className="w-4 h-4" />
            <span>New Integration</span>
          </button>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--red-bg)',
            border: '1px solid var(--red-border)',
            color: 'var(--red)',
          }}
        >
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1">
          <div
            className="rounded-xl overflow-hidden"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div
              className="px-4 py-3 text-sm font-semibold"
              style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
            >
              Configured Integrations
            </div>
            {loading ? (
              <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
                Loading integrations...
              </div>
            ) : integrations.length === 0 ? (
              <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
                No integrations found.
              </div>
            ) : (
              <div className="divide-y" style={{ borderColor: 'var(--border-glass)' }}>
                {integrations.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => handleSelect(item.name)}
                    className="w-full text-left p-4"
                    style={{
                      background:
                        selectedName === item.name ? 'var(--bg-glass-strong)' : 'transparent',
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                        {item.name}
                      </div>
                      <div
                        className="text-[11px] px-2 py-0.5 rounded"
                        style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                      >
                        {item.kind}
                      </div>
                    </div>
                    <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                      {item.api_server_url}
                    </div>
                    <div className="text-xs mt-2" style={{ color: 'var(--text-secondary)' }}>
                      token: {item.token_configured ? 'configured' : 'missing'}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="xl:col-span-2">
          <div
            className="rounded-xl overflow-hidden"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div
              className="px-4 py-3 text-sm font-semibold flex items-center justify-between"
              style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
            >
              <div>
                <div>Integration Editor</div>
                <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                  {editorMode === 'create'
                    ? 'Create a Kubernetes integration'
                    : `Editing ${selectedName ?? 'integration'}`}
                </div>
              </div>
              {editorMode === 'edit' && (
                <button
                  onClick={handleDelete}
                  className="px-3 py-1 text-xs rounded-lg flex items-center gap-1"
                  style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
                >
                  <Trash2 className="w-3 h-3" />
                  Delete
                </button>
              )}
            </div>

            <div className="p-4 space-y-4">
              <div>
                <label
                  className="block text-sm font-medium mb-1"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Name
                </label>
                <input
                  value={form.name}
                  onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                  disabled={editorMode === 'edit'}
                  className="w-full px-3 py-2 rounded-lg text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text)',
                  }}
                  placeholder="prod-kubernetes"
                />
              </div>

              <div>
                <label
                  className="block text-sm font-medium mb-1"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Integration Type
                </label>
                <input
                  value={form.kind}
                  disabled
                  className="w-full px-3 py-2 rounded-lg text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-secondary)',
                  }}
                />
              </div>

              <div>
                <label
                  className="block text-sm font-medium mb-1"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  kube-apiserver URL
                </label>
                <input
                  value={form.apiServerUrl}
                  onChange={(e) => setForm((prev) => ({ ...prev, apiServerUrl: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text)',
                  }}
                  placeholder="https://10.0.0.1:6443"
                />
              </div>

              <div>
                <label
                  className="block text-sm font-medium mb-1"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  kube-apiserver CA Certificate (PEM)
                </label>
                <textarea
                  value={form.caCertPem}
                  onChange={(e) => setForm((prev) => ({ ...prev, caCertPem: e.target.value }))}
                  rows={6}
                  className="w-full px-3 py-2 rounded-lg text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text)',
                  }}
                  placeholder="-----BEGIN CERTIFICATE-----"
                />
              </div>

              <div>
                <label
                  className="block text-sm font-medium mb-1"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Service Account Token
                </label>
                <textarea
                  value={form.serviceAccountToken}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, serviceAccountToken: e.target.value }))
                  }
                  rows={4}
                  className="w-full px-3 py-2 rounded-lg text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text)',
                  }}
                  placeholder="eyJhbGciOi..."
                />
                {editorMode === 'edit' && (
                  <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                    Token is write-only; provide a replacement token when updating.
                  </p>
                )}
              </div>

              {editorError && (
                <div className="text-xs" style={{ color: 'var(--red)' }}>
                  {editorError}
                </div>
              )}

              <div className="mt-4 flex justify-end gap-2">
                <button
                  disabled={saving}
                  onClick={handleCreateNew}
                  className="px-4 py-2 text-sm rounded-lg"
                  style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                >
                  Reset
                </button>
                <button
                  disabled={saving}
                  onClick={handleSave}
                  className="px-4 py-2 text-sm rounded-lg text-white"
                  style={{ background: 'var(--accent)' }}
                >
                  {saving ? 'Saving...' : editorMode === 'create' ? 'Create' : 'Update'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
