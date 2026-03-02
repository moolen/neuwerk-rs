import React, { useEffect, useMemo, useState } from 'react';
import { Copy, MoveDown, MoveUp, Plus, RefreshCw, Trash2 } from 'lucide-react';
import * as YAML from 'yaml';

import { KeyValueEditor } from '../components/KeyValueEditor';
import type {
  IntegrationView,
  PolicyCreateRequest,
  PolicyKubernetesSource,
  PolicyRule,
  PolicySourceGroup,
  PolicyTlsHttpHeadersMatch,
  PolicyTlsNameMatch,
} from '../types';
import {
  createPolicy,
  deletePolicy,
  getPolicy,
  listIntegrations,
  listPolicies,
  updatePolicy,
} from '../services/api';
import {
  clonePolicyRequest,
  createEmptyPolicyRequest,
  createEmptyRule,
  createEmptySourceGroup,
  createRuleTemplate,
  nextNamedId,
  normalizePolicyRequest,
  sanitizePolicyRequestForApi,
} from '../utils/policyModel';
import { validatePolicyRequest, type PolicyValidationIssue } from '../utils/policyValidation';

const RULE_TEMPLATES = [
  { id: 'dns_allow', label: 'DNS allowlist rule' },
  { id: 'l4_allow', label: 'L4 allow rule' },
  { id: 'tls_metadata', label: 'TLS metadata rule' },
  { id: 'tls_intercept', label: 'TLS intercept HTTP rule' },
] as const;

type RuleTemplateId = (typeof RULE_TEMPLATES)[number]['id'];

function listToText(values: string[]): string {
  return values.join('\n');
}

function textToList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function numberListToText(values: number[]): string {
  return values.join(', ');
}

function textToNumberList(value: string): number[] {
  return value
    .split(/[\n,]/)
    .map((entry) => Number(entry.trim()))
    .filter((entry) => Number.isFinite(entry))
    .map((entry) => Math.floor(entry));
}

function parseProtoKind(proto?: string): { kind: 'any' | 'tcp' | 'udp' | 'icmp' | 'custom'; custom: string } {
  const value = (proto ?? '').trim().toLowerCase();
  if (!value || value === 'any') return { kind: 'any', custom: '' };
  if (value === 'tcp') return { kind: 'tcp', custom: '' };
  if (value === 'udp') return { kind: 'udp', custom: '' };
  if (value === 'icmp') return { kind: 'icmp', custom: '' };
  return { kind: 'custom', custom: value };
}

function emptyTlsNameMatch(): PolicyTlsNameMatch {
  return {
    exact: [],
  };
}

function emptyTlsHeaders(): PolicyTlsHttpHeadersMatch {
  return {
    require_present: [],
    deny_present: [],
    exact: {},
    regex: {},
  };
}

function emptyKubernetesSource(): PolicyKubernetesSource {
  return {
    integration: '',
    pod_selector: {
      namespace: '',
      match_labels: {},
    },
  };
}

function moveItem<T>(items: T[], index: number, direction: -1 | 1): T[] {
  const nextIndex = index + direction;
  if (nextIndex < 0 || nextIndex >= items.length) return items;
  const next = [...items];
  const [item] = next.splice(index, 1);
  next.splice(nextIndex, 0, item);
  return next;
}

function duplicateId(base: string, existing: string[]): string {
  const prefix = base.trim().replace(/-\d+$/, '') || 'item';
  return nextNamedId(prefix, existing);
}

function formatIssues(issues: PolicyValidationIssue[]): string[] {
  return issues.map((issue) => `${issue.path}: ${issue.message}`);
}

interface StringListMapEditorProps {
  label: string;
  value: Record<string, string[]>;
  onChange: (next: Record<string, string[]>) => void;
  keyPlaceholder: string;
  valuePlaceholder: string;
}

const StringListMapEditor: React.FC<StringListMapEditorProps> = ({
  label,
  value,
  onChange,
  keyPlaceholder,
  valuePlaceholder,
}) => {
  const entries = Object.entries(value);

  const addRow = () => {
    const key = `key_${Date.now()}`;
    onChange({
      ...value,
      [key]: [],
    });
  };

  const removeRow = (key: string) => {
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const updateKey = (oldKey: string, nextKeyRaw: string) => {
    const nextKey = nextKeyRaw.trim() || `key_${Date.now()}`;
    const next: Record<string, string[]> = {};
    for (const [k, v] of entries) {
      if (k === oldKey) {
        next[nextKey] = v;
      } else {
        next[k] = v;
      }
    }
    onChange(next);
  };

  const updateValue = (key: string, nextValueRaw: string) => {
    onChange({
      ...value,
      [key]: textToList(nextValueRaw),
    });
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{label}</label>
        <button
          type="button"
          onClick={addRow}
          className="px-2 py-1 rounded text-xs"
          style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
        >
          Add
        </button>
      </div>
      <div className="space-y-2">
        {entries.map(([key, values], index) => (
          <div key={`${key}-${index}`} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-start">
            <input
              type="text"
              value={key}
              onChange={(e) => updateKey(key, e.target.value)}
              placeholder={keyPlaceholder}
              className="px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
            <input
              type="text"
              value={(values ?? []).join(', ')}
              onChange={(e) => updateValue(key, e.target.value)}
              placeholder={valuePlaceholder}
              className="px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
            <button
              type="button"
              onClick={() => removeRow(key)}
              className="p-2 rounded"
              style={{ color: 'var(--text-muted)' }}
              title="Remove row"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        ))}
        {!entries.length && (
          <div className="text-xs py-2 px-2 rounded" style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}>
            No entries configured.
          </div>
        )}
      </div>
    </div>
  );
};

interface TlsNameMatchEditorProps {
  label: string;
  value?: PolicyTlsNameMatch;
  onChange: (next?: PolicyTlsNameMatch) => void;
}

const TlsNameMatchEditor: React.FC<TlsNameMatchEditorProps> = ({ label, value, onChange }) => {
  const enabled = !!value;
  return (
    <div className="space-y-2 rounded p-3" style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}>
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{label}</label>
        <button
          type="button"
          onClick={() => onChange(enabled ? undefined : emptyTlsNameMatch())}
          className="px-2 py-1 text-xs rounded"
          style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
        >
          {enabled ? 'Disable' : 'Enable'}
        </button>
      </div>
      {enabled && value && (
        <>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Exact values (line or comma separated)</label>
            <textarea
              value={listToText(value.exact ?? [])}
              onChange={(e) => onChange({ ...value, exact: textToList(e.target.value) })}
              rows={2}
              className="w-full px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Regex</label>
            <input
              type="text"
              value={value.regex ?? ''}
              onChange={(e) => onChange({ ...value, regex: e.target.value })}
              className="w-full px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
          </div>
        </>
      )}
    </div>
  );
};

export const PoliciesPage: React.FC = () => {
  const [policies, setPolicies] = useState<import('../types').PolicyRecord[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [draft, setDraft] = useState<PolicyCreateRequest>(createEmptyPolicyRequest());
  const [editorMode, setEditorMode] = useState<'create' | 'edit'>('create');
  const [editorTargetId, setEditorTargetId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'builder' | 'yaml'>('builder');
  const [templateByGroup, setTemplateByGroup] = useState<Record<number, RuleTemplateId>>({});

  const integrationNames = useMemo(() => new Set(integrations.map((item) => item.name)), [integrations]);

  const validationIssues = useMemo(
    () => validatePolicyRequest(draft, { integrationNames }),
    [draft, integrationNames]
  );

  const payload = useMemo(() => sanitizePolicyRequestForApi(draft), [draft]);
  const yamlPreview = useMemo(() => YAML.stringify(payload, { indent: 2 }), [payload]);

  useEffect(() => {
    void loadAll();
  }, []);

  const loadAll = async () => {
    try {
      setLoading(true);
      setError(null);
      const [list, integrationList] = await Promise.all([listPolicies(), listIntegrations()]);
      const sorted = [...list].sort((a, b) => b.created_at.localeCompare(a.created_at));
      setPolicies(sorted);
      setIntegrations(integrationList.filter((entry) => entry.kind === 'kubernetes'));

      if (sorted.length && !selectedId) {
        await loadEditorForPolicy(sorted[0].id);
      } else if (!sorted.length) {
        handleCreate();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  };

  const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => {
    setDraft((prev) => {
      const next = clonePolicyRequest(prev);
      mutator(next);
      return next;
    });
  };

  const loadEditorForPolicy = async (policyId: string) => {
    try {
      setEditorError(null);
      setSelectedId(policyId);
      setEditorMode('edit');
      setEditorTargetId(policyId);
      const record = await getPolicy(policyId);
      setDraft(normalizePolicyRequest({ mode: record.mode, policy: record.policy }));
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to load policy');
    }
  };

  const handleCreate = () => {
    setEditorMode('create');
    setEditorTargetId(null);
    setSelectedId(null);
    setTemplateByGroup({});
    setDraft(createEmptyPolicyRequest());
    setEditorError(null);
  };

  const handleDelete = async (policyId: string) => {
    const confirmed = window.confirm('Delete this policy snapshot?');
    if (!confirmed) return;
    try {
      await deletePolicy(policyId);
      await loadAll();
      if (selectedId === policyId) setSelectedId(null);
      if (editorTargetId === policyId) handleCreate();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete policy');
    }
  };

  const handleSave = async () => {
    setEditorError(null);
    const issues = validatePolicyRequest(draft, { integrationNames });
    if (issues.length) {
      setEditorError(`Validation failed (${issues.length} issues). Review the list below.`);
      return;
    }

    setSaving(true);
    try {
      const request = sanitizePolicyRequestForApi(draft);
      if (editorMode === 'create') {
        const created = await createPolicy(request);
        setEditorMode('edit');
        setEditorTargetId(created.id);
        setSelectedId(created.id);
        setDraft(normalizePolicyRequest({ mode: created.mode, policy: created.policy }));
      } else if (editorTargetId) {
        const updated = await updatePolicy(editorTargetId, request);
        setDraft(normalizePolicyRequest({ mode: updated.mode, policy: updated.policy }));
      }
      await loadAll();
    } catch (err) {
      setEditorError(err instanceof Error ? err.message : 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  };

  const addGroup = () => {
    updateDraft((next) => {
      const id = nextNamedId('group', next.policy.source_groups.map((group) => group.id));
      const group = createEmptySourceGroup(id);
      group.priority = next.policy.source_groups.length;
      next.policy.source_groups.push(group);
    });
  };

  const duplicateGroup = (groupIndex: number) => {
    updateDraft((next) => {
      const existing = next.policy.source_groups.map((group) => group.id);
      const copy = clonePolicyRequest({ mode: next.mode, policy: { source_groups: [next.policy.source_groups[groupIndex]] } })
        .policy.source_groups[0];
      copy.id = duplicateId(copy.id, existing);
      next.policy.source_groups.splice(groupIndex + 1, 0, copy);
    });
  };

  const moveGroup = (groupIndex: number, direction: -1 | 1) => {
    updateDraft((next) => {
      next.policy.source_groups = moveItem(next.policy.source_groups, groupIndex, direction);
    });
  };

  const deleteGroup = (groupIndex: number) => {
    updateDraft((next) => {
      next.policy.source_groups.splice(groupIndex, 1);
    });
  };

  const addRule = (groupIndex: number) => {
    updateDraft((next) => {
      const group = next.policy.source_groups[groupIndex];
      const id = nextNamedId('rule', group.rules.map((rule) => rule.id));
      group.rules.push(createEmptyRule(id));
    });
  };

  const addRuleFromTemplate = (groupIndex: number) => {
    const template = templateByGroup[groupIndex] ?? 'l4_allow';
    updateDraft((next) => {
      const group = next.policy.source_groups[groupIndex];
      const id = nextNamedId('rule', group.rules.map((rule) => rule.id));
      group.rules.push(createRuleTemplate(template, id));
    });
  };

  const duplicateRule = (groupIndex: number, ruleIndex: number) => {
    updateDraft((next) => {
      const group = next.policy.source_groups[groupIndex];
      const copy = JSON.parse(JSON.stringify(group.rules[ruleIndex])) as PolicyRule;
      copy.id = duplicateId(copy.id, group.rules.map((rule) => rule.id));
      group.rules.splice(ruleIndex + 1, 0, copy);
    });
  };

  const moveRule = (groupIndex: number, ruleIndex: number, direction: -1 | 1) => {
    updateDraft((next) => {
      const group = next.policy.source_groups[groupIndex];
      group.rules = moveItem(group.rules, ruleIndex, direction);
    });
  };

  const deleteRule = (groupIndex: number, ruleIndex: number) => {
    updateDraft((next) => {
      next.policy.source_groups[groupIndex].rules.splice(ruleIndex, 1);
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>Policies</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Form-driven policy builder with live validation and canonical YAML preview.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadAll}
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
                    style={{ background: selectedId === policy.id ? 'var(--bg-glass-strong)' : 'transparent' }}
                    onClick={() => void loadEditorForPolicy(policy.id)}
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
                        onClick={(e) => {
                          e.stopPropagation();
                          void loadEditorForPolicy(policy.id);
                        }}
                        className="px-2 py-1 text-xs rounded-lg"
                        style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                      >
                        Edit
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleDelete(policy.id);
                        }}
                        className="px-2 py-1 text-xs rounded-lg"
                        style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
            <div className="px-4 py-3 text-sm font-semibold flex items-center justify-between" style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}>
              <div>
                <div>Policy Builder</div>
                <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                  {editorMode === 'create'
                    ? 'Creating a new policy snapshot'
                    : `Editing ${editorTargetId ? editorTargetId.slice(0, 8) : 'policy'}`}
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setActiveTab('builder')}
                  className="px-3 py-1 rounded"
                  style={{
                    background: activeTab === 'builder' ? 'var(--accent)' : 'var(--bg-input)',
                    color: activeTab === 'builder' ? '#fff' : 'var(--text-secondary)',
                  }}
                >
                  Builder
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('yaml')}
                  className="px-3 py-1 rounded"
                  style={{
                    background: activeTab === 'yaml' ? 'var(--accent)' : 'var(--bg-input)',
                    color: activeTab === 'yaml' ? '#fff' : 'var(--text-secondary)',
                  }}
                >
                  YAML Preview
                </button>
              </div>
            </div>

            {activeTab === 'builder' ? (
              <div className="p-4 space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Policy Mode</label>
                    <select
                      value={draft.mode}
                      onChange={(e) => setDraft((prev) => ({ ...prev, mode: e.target.value as PolicyCreateRequest['mode'] }))}
                      className="w-full px-3 py-2 rounded text-sm"
                      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                    >
                      <option value="disabled">disabled</option>
                      <option value="audit">audit</option>
                      <option value="enforce">enforce</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Default Policy</label>
                    <select
                      value={draft.policy.default_policy ?? 'deny'}
                      onChange={(e) => setDraft((prev) => ({ ...prev, policy: { ...prev.policy, default_policy: e.target.value as 'allow' | 'deny' } }))}
                      className="w-full px-3 py-2 rounded text-sm"
                      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                    >
                      <option value="deny">deny</option>
                      <option value="allow">allow</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>Source Groups</h3>
                    <button
                      type="button"
                      onClick={addGroup}
                      className="px-3 py-1.5 rounded text-xs"
                      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                    >
                      <span className="inline-flex items-center gap-1"><Plus className="w-3 h-3" /> Add Group</span>
                    </button>
                  </div>

                  {draft.policy.source_groups.map((group, gi) => (
                    <div key={`${group.id}-${gi}`} className="rounded-lg p-4 space-y-4" style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 flex-1">
                          <div>
                            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Group ID</label>
                            <input
                              type="text"
                              value={group.id}
                              onChange={(e) => updateDraft((next) => {
                                next.policy.source_groups[gi].id = e.target.value;
                              })}
                              className="w-full px-2 py-1 rounded text-sm"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                            />
                          </div>
                          <div>
                            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Priority</label>
                            <input
                              type="number"
                              min={0}
                              value={group.priority ?? ''}
                              onChange={(e) => updateDraft((next) => {
                                const value = e.target.value.trim();
                                next.policy.source_groups[gi].priority = value === '' ? undefined : Number(value);
                              })}
                              className="w-full px-2 py-1 rounded text-sm"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                            />
                          </div>
                          <div>
                            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Group Default Action</label>
                            <select
                              value={group.default_action ?? 'deny'}
                              onChange={(e) => updateDraft((next) => {
                                next.policy.source_groups[gi].default_action = e.target.value as 'allow' | 'deny';
                              })}
                              className="w-full px-2 py-1 rounded text-sm"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                            >
                              <option value="deny">deny</option>
                              <option value="allow">allow</option>
                            </select>
                          </div>
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          <button
                            type="button"
                            onClick={() => moveGroup(gi, -1)}
                            className="p-2 rounded"
                            style={{ color: 'var(--text-muted)' }}
                            title="Move up"
                          >
                            <MoveUp className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => moveGroup(gi, 1)}
                            className="p-2 rounded"
                            style={{ color: 'var(--text-muted)' }}
                            title="Move down"
                          >
                            <MoveDown className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => duplicateGroup(gi)}
                            className="p-2 rounded"
                            style={{ color: 'var(--text-muted)' }}
                            title="Duplicate group"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteGroup(gi)}
                            className="p-2 rounded"
                            style={{ color: 'var(--red)' }}
                            title="Delete group"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Source CIDRs (line/comma separated)</label>
                          <textarea
                            value={listToText(group.sources.cidrs)}
                            onChange={(e) => updateDraft((next) => {
                              next.policy.source_groups[gi].sources.cidrs = textToList(e.target.value);
                            })}
                            rows={3}
                            className="w-full px-2 py-1 rounded text-sm"
                            style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                          />
                        </div>
                        <div>
                          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Source IPv4s (line/comma separated)</label>
                          <textarea
                            value={listToText(group.sources.ips)}
                            onChange={(e) => updateDraft((next) => {
                              next.policy.source_groups[gi].sources.ips = textToList(e.target.value);
                            })}
                            rows={3}
                            className="w-full px-2 py-1 rounded text-sm"
                            style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                          />
                        </div>
                      </div>

                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Kubernetes Sources</h4>
                          <button
                            type="button"
                            onClick={() => updateDraft((next) => {
                              next.policy.source_groups[gi].sources.kubernetes.push(emptyKubernetesSource());
                            })}
                            className="px-2 py-1 rounded text-xs"
                            style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                          >
                            Add Kubernetes Source
                          </button>
                        </div>

                        {(group.sources.kubernetes ?? []).map((source, si) => {
                          const selectorType = source.pod_selector ? 'pod' : 'node';
                          return (
                            <div key={`k8s-${si}`} className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
                              <div className="flex items-center gap-2">
                                <select
                                  value={source.integration}
                                  onChange={(e) => updateDraft((next) => {
                                    next.policy.source_groups[gi].sources.kubernetes[si].integration = e.target.value;
                                  })}
                                  className="px-2 py-1 rounded text-sm min-w-56"
                                  style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                >
                                  <option value="">Select integration</option>
                                  {integrations.map((integration) => (
                                    <option key={integration.name} value={integration.name}>{integration.name}</option>
                                  ))}
                                </select>
                                <input
                                  type="text"
                                  value={source.integration}
                                  onChange={(e) => updateDraft((next) => {
                                    next.policy.source_groups[gi].sources.kubernetes[si].integration = e.target.value;
                                  })}
                                  placeholder="Or type integration name"
                                  className="flex-1 px-2 py-1 rounded text-sm"
                                  style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                />
                                <button
                                  type="button"
                                  onClick={() => updateDraft((next) => {
                                    next.policy.source_groups[gi].sources.kubernetes.splice(si, 1);
                                  })}
                                  className="p-2 rounded"
                                  style={{ color: 'var(--red)' }}
                                  title="Remove kubernetes source"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>

                              <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                                <label className="inline-flex items-center gap-1">
                                  <input
                                    type="radio"
                                    checked={selectorType === 'pod'}
                                    onChange={() => updateDraft((next) => {
                                      next.policy.source_groups[gi].sources.kubernetes[si].pod_selector = {
                                        namespace: '',
                                        match_labels: {},
                                      };
                                      delete next.policy.source_groups[gi].sources.kubernetes[si].node_selector;
                                    })}
                                  />
                                  Pod selector
                                </label>
                                <label className="inline-flex items-center gap-1">
                                  <input
                                    type="radio"
                                    checked={selectorType === 'node'}
                                    onChange={() => updateDraft((next) => {
                                      next.policy.source_groups[gi].sources.kubernetes[si].node_selector = {
                                        match_labels: {},
                                      };
                                      delete next.policy.source_groups[gi].sources.kubernetes[si].pod_selector;
                                    })}
                                  />
                                  Node selector
                                </label>
                              </div>

                              {source.pod_selector && (
                                <div className="space-y-3">
                                  <div>
                                    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Namespace</label>
                                    <input
                                      type="text"
                                      value={source.pod_selector.namespace}
                                      onChange={(e) => updateDraft((next) => {
                                        const pod = next.policy.source_groups[gi].sources.kubernetes[si].pod_selector;
                                        if (!pod) return;
                                        pod.namespace = e.target.value;
                                      })}
                                      className="w-full px-2 py-1 rounded text-sm"
                                      style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                    />
                                  </div>
                                  <KeyValueEditor
                                    label="Pod match_labels"
                                    value={source.pod_selector.match_labels}
                                    onChange={(nextMap) => updateDraft((next) => {
                                      const pod = next.policy.source_groups[gi].sources.kubernetes[si].pod_selector;
                                      if (!pod) return;
                                      pod.match_labels = nextMap;
                                    })}
                                    fieldPrefix={`group.${gi}.k8s.${si}.pod_labels`}
                                    errors={{}}
                                    keyPlaceholder="label key"
                                    valuePlaceholder="label value"
                                  />
                                </div>
                              )}

                              {source.node_selector && (
                                <KeyValueEditor
                                  label="Node match_labels"
                                  value={source.node_selector.match_labels}
                                  onChange={(nextMap) => updateDraft((next) => {
                                    const node = next.policy.source_groups[gi].sources.kubernetes[si].node_selector;
                                    if (!node) return;
                                    node.match_labels = nextMap;
                                  })}
                                  fieldPrefix={`group.${gi}.k8s.${si}.node_labels`}
                                  errors={{}}
                                  keyPlaceholder="label key"
                                  valuePlaceholder="label value"
                                />
                              )}
                            </div>
                          );
                        })}
                      </div>

                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Rules</h4>
                          <div className="flex items-center gap-2">
                            <select
                              value={templateByGroup[gi] ?? 'l4_allow'}
                              onChange={(e) => setTemplateByGroup((prev) => ({ ...prev, [gi]: e.target.value as RuleTemplateId }))}
                              className="px-2 py-1 rounded text-xs"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                            >
                              {RULE_TEMPLATES.map((template) => (
                                <option key={template.id} value={template.id}>{template.label}</option>
                              ))}
                            </select>
                            <button
                              type="button"
                              onClick={() => addRuleFromTemplate(gi)}
                              className="px-2 py-1 rounded text-xs"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                            >
                              Add Template Rule
                            </button>
                            <button
                              type="button"
                              onClick={() => addRule(gi)}
                              className="px-2 py-1 rounded text-xs"
                              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                            >
                              Add Blank Rule
                            </button>
                          </div>
                        </div>

                        {group.rules.map((rule, ri) => {
                          const proto = parseProtoKind(rule.match.proto);

                          return (
                            <div key={`${rule.id}-${ri}`} className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
                              <div className="flex items-start justify-between gap-3">
                                <div className="grid grid-cols-1 md:grid-cols-4 gap-2 flex-1">
                                  <input
                                    type="text"
                                    value={rule.id}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].id = e.target.value;
                                    })}
                                    placeholder="rule id"
                                    className="px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                  <input
                                    type="number"
                                    min={0}
                                    value={rule.priority ?? ''}
                                    onChange={(e) => updateDraft((next) => {
                                      const value = e.target.value.trim();
                                      next.policy.source_groups[gi].rules[ri].priority = value === '' ? undefined : Number(value);
                                    })}
                                    placeholder="priority"
                                    className="px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                  <select
                                    value={rule.action}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].action = e.target.value as 'allow' | 'deny';
                                    })}
                                    className="px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  >
                                    <option value="allow">allow</option>
                                    <option value="deny">deny</option>
                                  </select>
                                  <select
                                    value={rule.mode ?? 'enforce'}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].mode = e.target.value as 'audit' | 'enforce';
                                    })}
                                    className="px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  >
                                    <option value="enforce">enforce</option>
                                    <option value="audit">audit</option>
                                  </select>
                                </div>
                                <div className="flex items-center gap-1">
                                  <button type="button" onClick={() => moveRule(gi, ri, -1)} className="p-2 rounded" style={{ color: 'var(--text-muted)' }} title="Move up"><MoveUp className="w-4 h-4" /></button>
                                  <button type="button" onClick={() => moveRule(gi, ri, 1)} className="p-2 rounded" style={{ color: 'var(--text-muted)' }} title="Move down"><MoveDown className="w-4 h-4" /></button>
                                  <button type="button" onClick={() => duplicateRule(gi, ri)} className="p-2 rounded" style={{ color: 'var(--text-muted)' }} title="Duplicate"><Copy className="w-4 h-4" /></button>
                                  <button type="button" onClick={() => deleteRule(gi, ri)} className="p-2 rounded" style={{ color: 'var(--red)' }} title="Delete"><Trash2 className="w-4 h-4" /></button>
                                </div>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Protocol</label>
                                  <div className="flex gap-2">
                                    <select
                                      value={proto.kind}
                                      onChange={(e) => updateDraft((next) => {
                                        const value = e.target.value as 'any' | 'tcp' | 'udp' | 'icmp' | 'custom';
                                        if (value === 'custom') {
                                          next.policy.source_groups[gi].rules[ri].match.proto = proto.custom || '6';
                                        } else if (value === 'any') {
                                          delete next.policy.source_groups[gi].rules[ri].match.proto;
                                        } else {
                                          next.policy.source_groups[gi].rules[ri].match.proto = value;
                                        }
                                      })}
                                      className="px-2 py-1 rounded text-sm"
                                      style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                    >
                                      <option value="any">any</option>
                                      <option value="tcp">tcp</option>
                                      <option value="udp">udp</option>
                                      <option value="icmp">icmp</option>
                                      <option value="custom">custom numeric</option>
                                    </select>
                                    {proto.kind === 'custom' && (
                                      <input
                                        type="text"
                                        value={proto.custom}
                                        onChange={(e) => updateDraft((next) => {
                                          next.policy.source_groups[gi].rules[ri].match.proto = e.target.value;
                                        })}
                                        placeholder="0-255"
                                        className="px-2 py-1 rounded text-sm"
                                        style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                      />
                                    )}
                                  </div>
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>DNS hostname regex</label>
                                  <input
                                    type="text"
                                    value={rule.match.dns_hostname ?? ''}
                                    onChange={(e) => updateDraft((next) => {
                                      const value = e.target.value;
                                      if (!value.trim()) {
                                        delete next.policy.source_groups[gi].rules[ri].match.dns_hostname;
                                      } else {
                                        next.policy.source_groups[gi].rules[ri].match.dns_hostname = value;
                                      }
                                    })}
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Destination CIDRs</label>
                                  <textarea
                                    value={listToText(rule.match.dst_cidrs)}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.dst_cidrs = textToList(e.target.value);
                                    })}
                                    rows={2}
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Destination IPs</label>
                                  <textarea
                                    value={listToText(rule.match.dst_ips)}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.dst_ips = textToList(e.target.value);
                                    })}
                                    rows={2}
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Source ports</label>
                                  <input
                                    type="text"
                                    value={rule.match.src_ports.join(', ')}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.src_ports = textToList(e.target.value);
                                    })}
                                    placeholder="e.g. 1024-65535"
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Destination ports</label>
                                  <input
                                    type="text"
                                    value={rule.match.dst_ports.join(', ')}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.dst_ports = textToList(e.target.value);
                                    })}
                                    placeholder="e.g. 443, 8443-8444"
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>ICMP types</label>
                                  <input
                                    type="text"
                                    value={numberListToText(rule.match.icmp_types)}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.icmp_types = textToNumberList(e.target.value);
                                    })}
                                    placeholder="e.g. 0,3,8,11"
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>ICMP codes</label>
                                  <input
                                    type="text"
                                    value={numberListToText(rule.match.icmp_codes)}
                                    onChange={(e) => updateDraft((next) => {
                                      next.policy.source_groups[gi].rules[ri].match.icmp_codes = textToNumberList(e.target.value);
                                    })}
                                    placeholder="e.g. 0,4"
                                    className="w-full px-2 py-1 rounded text-sm"
                                    style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                  />
                                </div>
                              </div>

                              <div className="rounded p-3 space-y-3" style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg)' }}>
                                <div className="flex items-center justify-between">
                                  <h5 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>TLS Constraints</h5>
                                  <button
                                    type="button"
                                    onClick={() => updateDraft((next) => {
                                      const current = next.policy.source_groups[gi].rules[ri].match.tls;
                                      if (current) {
                                        delete next.policy.source_groups[gi].rules[ri].match.tls;
                                      } else {
                                        next.policy.source_groups[gi].rules[ri].match.tls = {
                                          mode: 'metadata',
                                          fingerprint_sha256: [],
                                          trust_anchors_pem: [],
                                          tls13_uninspectable: 'deny',
                                        };
                                      }
                                    })}
                                    className="px-2 py-1 rounded text-xs"
                                    style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                  >
                                    {rule.match.tls ? 'Disable TLS' : 'Enable TLS'}
                                  </button>
                                </div>

                                {rule.match.tls && (
                                  <div className="space-y-3">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                      <div>
                                        <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>TLS mode</label>
                                        <select
                                          value={rule.match.tls.mode ?? 'metadata'}
                                          onChange={(e) => updateDraft((next) => {
                                            const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                            if (!tls) return;
                                            const mode = e.target.value as 'metadata' | 'intercept';
                                            tls.mode = mode;
                                            if (mode === 'intercept') {
                                              delete tls.sni;
                                              delete tls.server_cn;
                                              delete tls.server_san;
                                              delete tls.server_dn;
                                              tls.fingerprint_sha256 = [];
                                              tls.trust_anchors_pem = [];
                                              tls.http = tls.http ?? {
                                                request: {
                                                  host: { exact: [] },
                                                  methods: [],
                                                  path: { exact: [], prefix: [] },
                                                  query: { keys_present: [], key_values_exact: {}, key_values_regex: {} },
                                                  headers: emptyTlsHeaders(),
                                                },
                                              };
                                            } else {
                                              delete tls.http;
                                            }
                                          })}
                                          className="w-full px-2 py-1 rounded text-sm"
                                          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                        >
                                          <option value="metadata">metadata</option>
                                          <option value="intercept">intercept</option>
                                        </select>
                                      </div>
                                      <div>
                                        <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>TLS 1.3 uninspectable</label>
                                        <select
                                          value={rule.match.tls.tls13_uninspectable ?? 'deny'}
                                          onChange={(e) => updateDraft((next) => {
                                            const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                            if (!tls) return;
                                            tls.tls13_uninspectable = e.target.value as 'allow' | 'deny';
                                          })}
                                          className="w-full px-2 py-1 rounded text-sm"
                                          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                        >
                                          <option value="deny">deny</option>
                                          <option value="allow">allow</option>
                                        </select>
                                      </div>
                                    </div>

                                    {(rule.match.tls.mode ?? 'metadata') === 'metadata' && (
                                      <div className="space-y-3">
                                        <TlsNameMatchEditor
                                          label="SNI matcher"
                                          value={rule.match.tls.sni}
                                          onChange={(nextValue) => updateDraft((next) => {
                                            const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                            if (!tls) return;
                                            tls.sni = nextValue;
                                          })}
                                        />
                                        <TlsNameMatchEditor
                                          label="Server SAN matcher"
                                          value={rule.match.tls.server_san}
                                          onChange={(nextValue) => updateDraft((next) => {
                                            const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                            if (!tls) return;
                                            tls.server_san = nextValue;
                                          })}
                                        />
                                        <TlsNameMatchEditor
                                          label="Server CN matcher"
                                          value={rule.match.tls.server_cn}
                                          onChange={(nextValue) => updateDraft((next) => {
                                            const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                            if (!tls) return;
                                            tls.server_cn = nextValue;
                                          })}
                                        />
                                        <div>
                                          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Legacy server_dn regex</label>
                                          <input
                                            type="text"
                                            value={rule.match.tls.server_dn ?? ''}
                                            onChange={(e) => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls) return;
                                              if (!e.target.value.trim()) {
                                                delete tls.server_dn;
                                              } else {
                                                tls.server_dn = e.target.value;
                                              }
                                            })}
                                            className="w-full px-2 py-1 rounded text-sm"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                          />
                                        </div>

                                        <div>
                                          <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>SHA256 fingerprints (line/comma separated)</label>
                                          <textarea
                                            value={listToText(rule.match.tls.fingerprint_sha256 ?? [])}
                                            onChange={(e) => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls) return;
                                              tls.fingerprint_sha256 = textToList(e.target.value);
                                            })}
                                            rows={2}
                                            className="w-full px-2 py-1 rounded text-sm"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                          />
                                        </div>

                                        <div className="space-y-2">
                                          <div className="flex items-center justify-between">
                                            <label className="text-xs" style={{ color: 'var(--text-muted)' }}>Trust anchors (PEM)</label>
                                            <button
                                              type="button"
                                              onClick={() => updateDraft((next) => {
                                                const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                                if (!tls) return;
                                                tls.trust_anchors_pem = [...(tls.trust_anchors_pem ?? []), ''];
                                              })}
                                              className="px-2 py-1 rounded text-xs"
                                              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                            >
                                              Add PEM
                                            </button>
                                          </div>
                                          {(rule.match.tls.trust_anchors_pem ?? []).map((pem, pi) => (
                                            <div key={`pem-${pi}`} className="space-y-1">
                                              <textarea
                                                value={pem}
                                                onChange={(e) => updateDraft((next) => {
                                                  const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                                  if (!tls) return;
                                                  tls.trust_anchors_pem[pi] = e.target.value;
                                                })}
                                                rows={4}
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />
                                              <button
                                                type="button"
                                                onClick={() => updateDraft((next) => {
                                                  const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                                  if (!tls) return;
                                                  tls.trust_anchors_pem.splice(pi, 1);
                                                })}
                                                className="text-xs"
                                                style={{ color: 'var(--red)' }}
                                              >
                                                Remove PEM
                                              </button>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {(rule.match.tls.mode ?? 'metadata') === 'intercept' && (
                                      <div className="space-y-4">
                                        <div className="flex items-center gap-2">
                                          <button
                                            type="button"
                                            className="px-2 py-1 rounded text-xs"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                            onClick={() => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls) return;
                                              tls.http = tls.http ?? {};
                                              tls.http.request = tls.http.request ?? {
                                                host: { exact: [] },
                                                methods: [],
                                                path: { exact: [], prefix: [] },
                                                query: { keys_present: [], key_values_exact: {}, key_values_regex: {} },
                                                headers: emptyTlsHeaders(),
                                              };
                                            })}
                                          >
                                            Enable request constraints
                                          </button>
                                          <button
                                            type="button"
                                            className="px-2 py-1 rounded text-xs"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                            onClick={() => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls?.http) return;
                                              delete tls.http.request;
                                            })}
                                          >
                                            Disable request constraints
                                          </button>
                                        </div>

                                        {rule.match.tls.http?.request && (
                                          <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
                                            <h6 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>HTTP request</h6>
                                            <TlsNameMatchEditor
                                              label="Host matcher"
                                              value={rule.match.tls.http.request.host}
                                              onChange={(nextValue) => updateDraft((next) => {
                                                const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                if (!request) return;
                                                request.host = nextValue;
                                              })}
                                            />

                                            <div>
                                              <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Methods</label>
                                              <input
                                                type="text"
                                                value={(rule.match.tls.http.request.methods ?? []).join(', ')}
                                                onChange={(e) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.methods = textToList(e.target.value).map((method) => method.toUpperCase());
                                                })}
                                                placeholder="GET, POST"
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />
                                            </div>

                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                              <div>
                                                <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Path exact</label>
                                                <textarea
                                                  rows={2}
                                                  value={listToText(rule.match.tls.http.request.path?.exact ?? [])}
                                                  onChange={(e) => updateDraft((next) => {
                                                    const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                    if (!request) return;
                                                    request.path = request.path ?? { exact: [], prefix: [] };
                                                    request.path.exact = textToList(e.target.value);
                                                  })}
                                                  className="w-full px-2 py-1 rounded text-sm"
                                                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                                />
                                              </div>
                                              <div>
                                                <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Path prefix</label>
                                                <textarea
                                                  rows={2}
                                                  value={listToText(rule.match.tls.http.request.path?.prefix ?? [])}
                                                  onChange={(e) => updateDraft((next) => {
                                                    const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                    if (!request) return;
                                                    request.path = request.path ?? { exact: [], prefix: [] };
                                                    request.path.prefix = textToList(e.target.value);
                                                  })}
                                                  className="w-full px-2 py-1 rounded text-sm"
                                                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                                />
                                              </div>
                                            </div>

                                            <div>
                                              <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Path regex</label>
                                              <input
                                                type="text"
                                                value={rule.match.tls.http.request.path?.regex ?? ''}
                                                onChange={(e) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.path = request.path ?? { exact: [], prefix: [] };
                                                  request.path.regex = e.target.value;
                                                })}
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />
                                            </div>

                                            <div>
                                              <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>Query keys_present</label>
                                              <input
                                                type="text"
                                                value={(rule.match.tls.http.request.query?.keys_present ?? []).join(', ')}
                                                onChange={(e) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.query = request.query ?? { keys_present: [], key_values_exact: {}, key_values_regex: {} };
                                                  request.query.keys_present = textToList(e.target.value);
                                                })}
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />
                                            </div>

                                            <StringListMapEditor
                                              label="Query key_values_exact"
                                              value={rule.match.tls.http.request.query?.key_values_exact ?? {}}
                                              onChange={(nextMap) => updateDraft((next) => {
                                                const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                if (!request) return;
                                                request.query = request.query ?? { keys_present: [], key_values_exact: {}, key_values_regex: {} };
                                                request.query.key_values_exact = nextMap;
                                              })}
                                              keyPlaceholder="query key"
                                              valuePlaceholder="v1, v2"
                                            />

                                            <KeyValueEditor
                                              label="Query key_values_regex"
                                              value={rule.match.tls.http.request.query?.key_values_regex ?? {}}
                                              onChange={(nextMap) => updateDraft((next) => {
                                                const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                if (!request) return;
                                                request.query = request.query ?? { keys_present: [], key_values_exact: {}, key_values_regex: {} };
                                                request.query.key_values_regex = nextMap;
                                              })}
                                              fieldPrefix={`group.${gi}.rule.${ri}.tls.http.query.regex`}
                                              errors={{}}
                                              keyPlaceholder="query key"
                                              valuePlaceholder="regex"
                                            />

                                            <div className="space-y-3">
                                              <div className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>Request headers</div>
                                              <input
                                                type="text"
                                                value={(rule.match.tls.http.request.headers?.require_present ?? []).join(', ')}
                                                onChange={(e) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.headers = request.headers ?? emptyTlsHeaders();
                                                  request.headers.require_present = textToList(e.target.value);
                                                })}
                                                placeholder="require_present"
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />
                                              <input
                                                type="text"
                                                value={(rule.match.tls.http.request.headers?.deny_present ?? []).join(', ')}
                                                onChange={(e) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.headers = request.headers ?? emptyTlsHeaders();
                                                  request.headers.deny_present = textToList(e.target.value);
                                                })}
                                                placeholder="deny_present"
                                                className="w-full px-2 py-1 rounded text-sm"
                                                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                              />

                                              <StringListMapEditor
                                                label="Headers exact"
                                                value={rule.match.tls.http.request.headers?.exact ?? {}}
                                                onChange={(nextMap) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.headers = request.headers ?? emptyTlsHeaders();
                                                  request.headers.exact = nextMap;
                                                })}
                                                keyPlaceholder="header"
                                                valuePlaceholder="v1, v2"
                                              />

                                              <KeyValueEditor
                                                label="Headers regex"
                                                value={rule.match.tls.http.request.headers?.regex ?? {}}
                                                onChange={(nextMap) => updateDraft((next) => {
                                                  const request = next.policy.source_groups[gi].rules[ri].match.tls?.http?.request;
                                                  if (!request) return;
                                                  request.headers = request.headers ?? emptyTlsHeaders();
                                                  request.headers.regex = nextMap;
                                                })}
                                                fieldPrefix={`group.${gi}.rule.${ri}.tls.http.request.headers.regex`}
                                                errors={{}}
                                                keyPlaceholder="header"
                                                valuePlaceholder="regex"
                                              />
                                            </div>
                                          </div>
                                        )}

                                        <div className="flex items-center gap-2">
                                          <button
                                            type="button"
                                            className="px-2 py-1 rounded text-xs"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                            onClick={() => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls) return;
                                              tls.http = tls.http ?? {};
                                              tls.http.response = tls.http.response ?? {
                                                headers: emptyTlsHeaders(),
                                              };
                                            })}
                                          >
                                            Enable response constraints
                                          </button>
                                          <button
                                            type="button"
                                            className="px-2 py-1 rounded text-xs"
                                            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}
                                            onClick={() => updateDraft((next) => {
                                              const tls = next.policy.source_groups[gi].rules[ri].match.tls;
                                              if (!tls?.http) return;
                                              delete tls.http.response;
                                            })}
                                          >
                                            Disable response constraints
                                          </button>
                                        </div>

                                        {rule.match.tls.http?.response && (
                                          <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
                                            <h6 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>HTTP response headers</h6>
                                            <input
                                              type="text"
                                              value={(rule.match.tls.http.response.headers?.require_present ?? []).join(', ')}
                                              onChange={(e) => updateDraft((next) => {
                                                const response = next.policy.source_groups[gi].rules[ri].match.tls?.http?.response;
                                                if (!response) return;
                                                response.headers = response.headers ?? emptyTlsHeaders();
                                                response.headers.require_present = textToList(e.target.value);
                                              })}
                                              placeholder="require_present"
                                              className="w-full px-2 py-1 rounded text-sm"
                                              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                            />
                                            <input
                                              type="text"
                                              value={(rule.match.tls.http.response.headers?.deny_present ?? []).join(', ')}
                                              onChange={(e) => updateDraft((next) => {
                                                const response = next.policy.source_groups[gi].rules[ri].match.tls?.http?.response;
                                                if (!response) return;
                                                response.headers = response.headers ?? emptyTlsHeaders();
                                                response.headers.deny_present = textToList(e.target.value);
                                              })}
                                              placeholder="deny_present"
                                              className="w-full px-2 py-1 rounded text-sm"
                                              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
                                            />

                                            <StringListMapEditor
                                              label="Headers exact"
                                              value={rule.match.tls.http.response.headers?.exact ?? {}}
                                              onChange={(nextMap) => updateDraft((next) => {
                                                const response = next.policy.source_groups[gi].rules[ri].match.tls?.http?.response;
                                                if (!response) return;
                                                response.headers = response.headers ?? emptyTlsHeaders();
                                                response.headers.exact = nextMap;
                                              })}
                                              keyPlaceholder="header"
                                              valuePlaceholder="v1, v2"
                                            />

                                            <KeyValueEditor
                                              label="Headers regex"
                                              value={rule.match.tls.http.response.headers?.regex ?? {}}
                                              onChange={(nextMap) => updateDraft((next) => {
                                                const response = next.policy.source_groups[gi].rules[ri].match.tls?.http?.response;
                                                if (!response) return;
                                                response.headers = response.headers ?? emptyTlsHeaders();
                                                response.headers.regex = nextMap;
                                              })}
                                              fieldPrefix={`group.${gi}.rule.${ri}.tls.http.response.headers.regex`}
                                              errors={{}}
                                              keyPlaceholder="header"
                                              valuePlaceholder="regex"
                                            />
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}

                        {!group.rules.length && (
                          <div className="text-xs py-2 px-2 rounded" style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}>
                            No rules configured.
                          </div>
                        )}
                      </div>
                    </div>
                  ))}

                  {!draft.policy.source_groups.length && (
                    <div className="text-xs py-3 px-3 rounded" style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}>
                      No source groups configured.
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-4">
                <div className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
                  Generated from the form model. This preview is canonical and read-only.
                </div>
                <pre
                  className="rounded-lg p-3 text-xs overflow-auto"
                  style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)', maxHeight: '70vh' }}
                >
                  {yamlPreview}
                </pre>
              </div>
            )}
          </div>

          {validationIssues.length > 0 && (
            <div className="rounded-lg p-4" style={{ background: 'var(--amber-bg)', border: '1px solid var(--amber-border)', color: 'var(--amber)' }}>
              <div className="font-semibold text-sm mb-2">Validation issues ({validationIssues.length})</div>
              <div className="text-xs space-y-1 max-h-48 overflow-auto">
                {formatIssues(validationIssues).map((line, idx) => (
                  <div key={`issue-${idx}`}>{line}</div>
                ))}
              </div>
            </div>
          )}

          {editorError && (
            <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
              {editorError}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <button
              disabled={saving}
              onClick={() => {
                if (editorMode === 'edit' && editorTargetId) {
                  void loadEditorForPolicy(editorTargetId);
                } else {
                  handleCreate();
                }
              }}
              className="px-4 py-2 text-sm rounded-lg"
              style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
            >
              Revert
            </button>
            <button
              disabled={saving || validationIssues.length > 0}
              onClick={handleSave}
              className="px-4 py-2 text-sm rounded-lg text-white"
              style={{
                background: saving || validationIssues.length > 0 ? 'var(--text-muted)' : 'var(--accent)',
                cursor: saving || validationIssues.length > 0 ? 'not-allowed' : 'pointer',
              }}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
