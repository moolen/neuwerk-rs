import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { PolicyRecord } from '../../types';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycle';
import { loadPolicyBuilderRemote } from './policyBuilderRemote';
import {
  buildCloseSourceGroupEditor,
  buildLoadAll,
  buildOpenSourceGroupEditor,
  buildSelectPolicy,
} from './policyBuilderLifecycleLoad';

vi.mock('./policyBuilderRemote', () => ({
  loadPolicyBuilderRemote: vi.fn(),
  loadPolicyDraftRemote: vi.fn(),
}));

describe('policyBuilderLifecycle helpers', () => {
  beforeEach(() => {
    vi.mocked(loadPolicyBuilderRemote).mockReset();
  });

  it('derives initial load follow-up action', () => {
    const policies = [{ id: 'p-1' }, { id: 'p-2' }] as PolicyRecord[];
    expect(deriveLoadAllFollowUp(policies, null)).toEqual({ kind: 'select-first', policyId: 'p-1' });
    expect(deriveLoadAllFollowUp(policies, 'p-2')).toEqual({ kind: 'none' });
    expect(deriveLoadAllFollowUp([], null)).toEqual({ kind: 'create' });
  });

  it('normalizes unknown errors to fallback message', () => {
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('boom');
    expect(errorMessage('x', 'fallback')).toBe('fallback');
  });

  it('tracks selected policy separately from editor target and closes overlay', () => {
    const selectedPolicyIds: Array<string | null> = [];
    let editorTargetId: string | null = 'editor-1';
    const overlayModes: Array<'closed' | 'create-group' | 'edit-group'> = [];
    const overlaySourceGroupIds: Array<string | null> = [];

    const selectPolicy = buildSelectPolicy({
      setSelectedPolicyId: (value) => selectedPolicyIds.push(value),
      setOverlayMode: (value) =>
        overlayModes.push(value),
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });

    selectPolicy('p-2');

    expect(selectedPolicyIds).toEqual(['p-2']);
    expect(editorTargetId).toBe('editor-1');
    expect(overlayModes).toEqual(['closed']);
    expect(overlaySourceGroupIds).toEqual([null]);
  });

  it('starts overlay closed and can open edit/create modes', () => {
    let overlayMode: 'closed' | 'create-group' | 'edit-group' = 'closed';
    const overlayModes: Array<'closed' | 'create-group' | 'edit-group'> = [];
    const overlaySourceGroupIds: Array<string | null> = [];

    const openSourceGroupEditor = buildOpenSourceGroupEditor({
      setOverlayMode: (value) => {
        overlayMode = value;
        overlayModes.push(value);
      },
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });
    const closeSourceGroupEditor = buildCloseSourceGroupEditor({
      setOverlayMode: (value) => {
        overlayMode = value;
        overlayModes.push(value);
      },
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });

    expect(overlayMode).toBe('closed');
    closeSourceGroupEditor();
    openSourceGroupEditor(null);
    openSourceGroupEditor('group-1');

    expect(overlayModes).toEqual(['closed', 'create-group', 'edit-group']);
    expect(overlaySourceGroupIds).toEqual([null, null, 'group-1']);
  });

  it('uses selectedPolicyId for load follow-up, not legacy selectedId alias', async () => {
    vi.mocked(loadPolicyBuilderRemote).mockResolvedValue({
      policies: [{ id: 'p-1' }] as PolicyRecord[],
      integrations: [],
    });

    const selectedPolicyIds: Array<string | null> = [];
    const selectedIds: Array<string | null> = [];
    const loadAll = buildLoadAll(
      {
        selectedPolicyId: null,
        selectedId: 'legacy-selected-id',
        setSelectedPolicyId: (value) => selectedPolicyIds.push(value),
        setSelectedId: (value) => selectedIds.push(value),
        setLoading: () => undefined,
        setError: () => undefined,
        setPolicies: () => undefined,
        setIntegrations: () => undefined,
      } as never,
      async () => undefined,
      () => undefined,
    );

    await loadAll();

    expect(selectedPolicyIds).toEqual(['p-1']);
    expect(selectedIds).toEqual([]);
  });
});
