import React, { useEffect, useRef, useState } from 'react';
import { Plus, Trash2, Pencil, RefreshCw } from 'lucide-react';
import Editor, { useMonaco } from '@monaco-editor/react';
import { configureMonacoYaml } from 'monaco-yaml';
import * as YAML from 'yaml';
import type { PolicyRecord, PolicyCreateRequest } from '../types';
import { listPolicies, getPolicy, createPolicy, updatePolicy, deletePolicy } from '../services/api';
import { useTheme } from '../components/ThemeProvider';
import { POLICY_REQUEST_SCHEMA } from '../utils/policySchema';

const DEFAULT_POLICY_TEMPLATE: PolicyCreateRequest = {
  mode: 'enforce',
  policy: {
    default_policy: 'deny',
    source_groups: [],
  },
};

const isPolicyMode = (value: unknown): value is PolicyCreateRequest['mode'] =>
  value === 'disabled' || value === 'audit' || value === 'enforce';

export const PoliciesPage: React.FC = () => {
  const { theme } = useTheme();
  const monaco = useMonaco();
  const monacoConfigured = useRef(false);
  const [policies, setPolicies] = useState<PolicyRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editorText, setEditorText] = useState('');
  const [editorMode, setEditorMode] = useState<'create' | 'edit'>('create');
  const [editorTargetId, setEditorTargetId] = useState<string | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [editorLoading, setEditorLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!monaco || monacoConfigured.current) return;
    configureMonacoYaml(monaco, {
      enableSchemaRequest: false,
      hover: true,
      completion: true,
      validate: true,
      format: true,
      schemas: [
        {
          uri: 'inmemory://model/policy.schema.json',
          fileMatch: ['policy.yaml'],
          schema: POLICY_REQUEST_SCHEMA,
        },
      ],
    });
    monacoConfigured.current = true;
  }, [monaco]);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await listPolicies();
      const sorted = [...list].sort((a, b) => b.created_at.localeCompare(a.created_at));
      setPolicies(sorted);
      if (sorted.length && !selectedId) {
        await loadEditorForPolicy(sorted[0].id);
      } else if (sorted.length === 0 && editorText.trim() === '') {
        handleCreate();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  };

  const loadEditorForPolicy = async (policyId: string) => {
    setEditorLoading(true);
    setEditorError(null);
    setSelectedId(policyId);
    setEditorMode('edit');
    setEditorTargetId(policyId);
    try {
      const record = await getPolicy(policyId);
      const request: PolicyCreateRequest = { mode: record.mode, policy: record.policy };
      setEditorText(YAML.stringify(request, { indent: 2 }));
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to load policy');
    } finally {
      setEditorLoading(false);
    }
  };

  const handleCreate = () => {
    setEditorMode('create');
    setEditorTargetId(null);
    setEditorText(YAML.stringify(DEFAULT_POLICY_TEMPLATE, { indent: 2 }));
    setEditorError(null);
    setSelectedId(null);
  };

  const handleEdit = async (policyId: string) => {
    await loadEditorForPolicy(policyId);
  };

  const handleDelete = async (policyId: string) => {
    const confirmed = window.confirm('Delete this policy?');
    if (!confirmed) return;
    try {
      await deletePolicy(policyId);
      await loadPolicies();
      if (selectedId === policyId) {
        setSelectedId(null);
      }
      if (editorTargetId === policyId) {
        handleCreate();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete policy');
    }
  };

  const handleEditorSubmit = async () => {
    setSaving(true);
    setEditorError(null);
    try {
      const parsed = YAML.parse(editorText) as Record<string, unknown> | null;
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('YAML must be an object with mode and policy fields');
      }
      const mode = parsed.mode;
      const policy = parsed.policy;
      if (!isPolicyMode(mode)) {
        throw new Error('mode must be "disabled", "enforce", or "audit"');
      }
      if (!policy || typeof policy !== 'object') {
        throw new Error('policy must be an object');
      }
      const request: PolicyCreateRequest = { mode, policy: policy as Record<string, unknown> };
      if (editorMode === 'create') {
        const created = await createPolicy(request);
        setEditorMode('edit');
        setEditorTargetId(created.id);
        setSelectedId(created.id);
        setEditorText(YAML.stringify({ mode: created.mode, policy: created.policy }, { indent: 2 }));
      } else if (editorTargetId) {
        const updated = await updatePolicy(editorTargetId, request);
        setEditorText(YAML.stringify({ mode: updated.mode, policy: updated.policy }, { indent: 2 }));
      }
      await loadPolicies();
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (editorMode === 'edit' && editorTargetId) {
      await loadEditorForPolicy(editorTargetId);
      return;
    }
    handleCreate();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>Policies</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Manage policy snapshots. Edit policies in YAML with schema-aware hints.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadPolicies}
            className="px-3 py-2 text-sm rounded-lg border"
            style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-muted)' }}
          >
            <span className="flex items-center gap-2"><RefreshCw className="w-4 h-4" />Refresh</span>
          </button>
          <button
            onClick={handleCreate}
            className="px-4 py-2 text-white rounded-lg flex items-center space-x-2 transition-colors"
            style={{ background: 'var(--accent)' }}
          >
            <Plus className="w-4 h-4" />
            <span>New Policy</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1">
          <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
            <div className="px-4 py-3 text-sm font-semibold" style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}>
              Policy Snapshots
            </div>
            {loading ? (
              <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>Loading policies...</div>
            ) : policies.length === 0 ? (
              <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>No policies found.</div>
            ) : (
              <div className="divide-y" style={{ borderColor: 'var(--border-glass)' }}>
                {policies.map((policy) => (
                  <div
                    key={policy.id}
                    className="p-4 cursor-pointer"
                    style={{
                      background: selectedId === policy.id ? 'var(--bg-glass-strong)' : 'transparent',
                    }}
                    onClick={() => handleEdit(policy.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{policy.id.slice(0, 8)}</div>
                        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{new Date(policy.created_at).toLocaleString()}</div>
                      </div>
                      <div className="text-xs px-2 py-1 rounded" style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}>
                        {policy.mode}
                      </div>
                    </div>
                    <div className="mt-3 flex items-center gap-2">
                      <button
                        onClick={(e) => { e.stopPropagation(); handleEdit(policy.id); }}
                        className="px-2 py-1 text-xs rounded-lg flex items-center gap-1"
                        style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                      >
                        <Pencil className="w-3 h-3" /> Edit
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(policy.id); }}
                        className="px-2 py-1 text-xs rounded-lg flex items-center gap-1"
                        style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
                      >
                        <Trash2 className="w-3 h-3" /> Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="xl:col-span-2">
          <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
            <div className="px-4 py-3 text-sm font-semibold flex items-center justify-between" style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}>
              <div>
                <div>Policy Editor</div>
                <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                  {editorMode === 'create'
                    ? 'Creating a new policy'
                    : `Editing ${editorTargetId ? editorTargetId.slice(0, 8) : 'policy'}`}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCreate}
                  className="px-3 py-1 text-xs rounded-lg"
                  style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                >
                  New
                </button>
              </div>
            </div>
            <div className="p-4">
              {editorLoading ? (
                <div className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading policy...</div>
              ) : (
                <div
                  className="w-full overflow-hidden rounded-lg"
                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)' }}
                >
                  <Editor
                    value={editorText}
                    onChange={(value) => setEditorText(value ?? '')}
                    language="yaml"
                    theme={theme === 'dark' ? 'vs-dark' : 'vs'}
                    path="policy.yaml"
                    height="70vh"
                    options={{
                      minimap: { enabled: false },
                      lineNumbers: 'on',
                      fontSize: 12,
                      scrollBeyondLastLine: false,
                      wordWrap: 'on',
                      tabSize: 2,
                      insertSpaces: true,
                      quickSuggestions: true,
                      suggestOnTriggerCharacters: true,
                      automaticLayout: true,
                    }}
                  />
                </div>
              )}
              {editorError && (
                <div className="mt-3 text-xs" style={{ color: 'var(--red)' }}>{editorError}</div>
              )}
              <div className="mt-4 flex justify-end gap-2">
                <button
                  disabled={saving}
                  onClick={handleReset}
                  className="px-4 py-2 text-sm rounded-lg"
                  style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                >
                  Revert
                </button>
                <button
                  disabled={saving}
                  onClick={handleEditorSubmit}
                  className="px-4 py-2 text-sm rounded-lg text-white"
                  style={{ background: 'var(--accent)' }}
                >
                  {saving ? 'Saving...' : 'Save'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
