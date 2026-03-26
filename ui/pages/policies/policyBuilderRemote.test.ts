import { describe, expect, it, vi } from 'vitest';

import type { IntegrationView, PolicyCreateRequest, PolicyRecord } from '../../types';
import {
  deletePolicyRemote,
  filterKubernetesIntegrations,
  loadPolicyBuilderRemote,
  loadPolicyDraftRemote,
  savePolicyRemote,
  sortPoliciesByCreatedAt,
} from './policyBuilderRemote';

vi.mock('../../services/api', () => ({
  createPolicy: vi.fn(),
  deletePolicy: vi.fn(),
  getPolicy: vi.fn(),
  listIntegrations: vi.fn(),
  listPolicies: vi.fn(),
  updatePolicy: vi.fn(),
}));

import * as api from '../../services/api';

function sampleDraft(): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_policy: 'deny',
      source_groups: [],
    },
  };
}

describe('policyBuilderRemote', () => {
  it('sorts policies newest first', () => {
    const sorted = sortPoliciesByCreatedAt([
      { id: 'a', created_at: '2026-01-01T00:00:00Z', mode: 'enforce', policy: { source_groups: [] } },
      { id: 'b', created_at: '2026-02-01T00:00:00Z', mode: 'enforce', policy: { source_groups: [] } },
    ] as PolicyRecord[]);
    expect(sorted.map((item) => item.id)).toEqual(['b', 'a']);
  });

  it('filters integrations to kubernetes', () => {
    const result = filterKubernetesIntegrations([
      { name: 'k1', kind: 'kubernetes' },
      { name: 'x1', kind: 'other' },
    ] as IntegrationView[]);
    expect(result.map((entry) => entry.name)).toEqual(['k1']);
  });

  it('loads sorted policies and kubernetes integrations', async () => {
    vi.mocked(api.listPolicies).mockResolvedValue([
      { id: 'a', created_at: '2026-01-01T00:00:00Z', mode: 'enforce', policy: { source_groups: [] } },
      { id: 'b', created_at: '2026-02-01T00:00:00Z', mode: 'audit', policy: { source_groups: [] } },
    ] as PolicyRecord[]);
    vi.mocked(api.listIntegrations).mockResolvedValue([
      { name: 'k1', kind: 'kubernetes' },
      { name: 'x1', kind: 'other' },
    ] as IntegrationView[]);

    const result = await loadPolicyBuilderRemote();

    expect(result.policies.map((item) => item.id)).toEqual(['b', 'a']);
    expect(result.integrations.map((item) => item.name)).toEqual(['k1']);
  });

  it('loads and normalizes a policy draft', async () => {
    vi.mocked(api.getPolicy).mockResolvedValue({
      id: 'p1',
      created_at: '2026-02-01T00:00:00Z',
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: { cidrs: [], ips: [], kubernetes: [] },
            rules: [{ id: 'r1', action: 'allow', match: { proto: 6 } }],
          },
        ],
      },
    } as unknown as PolicyRecord);

    const draft = await loadPolicyDraftRemote('p1');
    expect(draft.policy.source_groups[0].rules[0].match.proto).toBe('6');
  });

  it('saves create and edit policy paths', async () => {
    vi.mocked(api.createPolicy).mockResolvedValue({
      id: 'new-id',
      created_at: '2026-02-01T00:00:00Z',
      mode: 'enforce',
      policy: { source_groups: [] },
    } as unknown as PolicyRecord);
    vi.mocked(api.updatePolicy).mockResolvedValue({
      id: 'existing-id',
      created_at: '2026-02-01T00:00:00Z',
      mode: 'audit',
      policy: { source_groups: [] },
    } as unknown as PolicyRecord);

    const created = await savePolicyRemote('create', null, sampleDraft());
    const updated = await savePolicyRemote('edit', 'existing-id', sampleDraft());

    expect(created.editorMode).toBe('edit');
    expect(created.editorTargetId).toBe('new-id');
    expect(created.selectedPolicyId).toBe('new-id');
    expect(updated.editorTargetId).toBe('existing-id');
    expect(updated.selectedPolicyId).toBeNull();
    expect(updated.draft.mode).toBe('audit');
  });

  it('deletes policy by id', async () => {
    vi.mocked(api.deletePolicy).mockResolvedValue();
    await deletePolicyRemote('p1');
    expect(api.deletePolicy).toHaveBeenCalledWith('p1');
  });
});
