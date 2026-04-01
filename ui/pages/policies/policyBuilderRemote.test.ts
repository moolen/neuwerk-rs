import { describe, expect, it, vi } from 'vitest';

import type { IntegrationView, PolicyCreateRequest } from '../../types';
import { createEmptyPolicyRequest } from '../../utils/policyModel';
import {
  filterKubernetesIntegrations,
  loadPolicyBuilderRemote,
  loadPolicyDraftRemote,
  savePolicyRemote,
} from './policyBuilderRemote';

vi.mock('../../services/api', () => ({
  getPolicy: vi.fn(),
  listIntegrations: vi.fn(),
  updatePolicy: vi.fn(),
}));

import * as api from '../../services/api';

function sampleDraft(): PolicyCreateRequest {
  return createEmptyPolicyRequest();
}

describe('policyBuilderRemote', () => {
  it('filters integrations to kubernetes', () => {
    const result = filterKubernetesIntegrations([
      { name: 'k1', kind: 'kubernetes' },
      { name: 'x1', kind: 'other' },
    ] as IntegrationView[]);
    expect(result.map((entry) => entry.name)).toEqual(['k1']);
  });

  it('loads the singleton policy draft and kubernetes integrations', async () => {
    vi.mocked(api.getPolicy).mockResolvedValue({
      default_policy: 'deny',
      source_groups: [],
    });
    vi.mocked(api.listIntegrations).mockResolvedValue([
      { name: 'k1', kind: 'kubernetes' },
      { name: 'x1', kind: 'other' },
    ] as IntegrationView[]);

    const result = await loadPolicyBuilderRemote();

    expect(result.draft.policy.default_policy).toBe('deny');
    expect(result.draft.policy.source_groups).toEqual([]);
    expect(result.integrations.map((item) => item.name)).toEqual(['k1']);
  });

  it('loads and normalizes the singleton policy draft', async () => {
    vi.mocked(api.getPolicy).mockResolvedValue({
      source_groups: [
        {
          id: 'g1',
          mode: 'audit',
          sources: { cidrs: [], ips: [], kubernetes: [] },
          rules: [{ id: 'r1', action: 'allow', match: { proto: 6 } }],
        },
      ],
    });

    const draft = await loadPolicyDraftRemote('ignored-legacy-id');
    expect(draft.policy.source_groups[0].rules[0].match.proto).toBe('6');
  });

  it('saves the singleton policy through the shared API surface', async () => {
    vi.mocked(api.updatePolicy).mockResolvedValue({
      default_policy: 'deny',
      source_groups: [],
    });

    const updated = await savePolicyRemote('edit', 'singleton', sampleDraft());

    expect(api.updatePolicy).toHaveBeenCalledWith({
      default_policy: 'deny',
      source_groups: [],
    });
    expect(updated.editorMode).toBe('edit');
    expect(updated.editorTargetId).toBe('singleton');
    expect(updated.selectedPolicyId).toBe('singleton');
    expect(updated.draft.policy.default_policy).toBe('deny');
  });
});
