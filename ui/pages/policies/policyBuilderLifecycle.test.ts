import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { PolicyRecord } from '../../types';
import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycle';
import { buildHandleDelete } from './policyBuilderLifecycleDelete';
import { buildHandleSave } from './policyBuilderLifecycleSave';
import {
  deletePolicyRemote,
  loadPolicyBuilderRemote,
  savePolicyRemote,
} from './policyBuilderRemote';
import {
  buildCloseSourceGroupEditor,
  buildLoadAll,
  buildOpenSourceGroupEditor,
  buildSelectPolicy,
} from './policyBuilderLifecycleLoad';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';
import { usePolicyBuilder } from './usePolicyBuilder';
import { usePolicyBuilderState } from './usePolicyBuilderState';

vi.mock('./policyBuilderRemote', () => ({
  deletePolicyRemote: vi.fn(),
  loadPolicyBuilderRemote: vi.fn(),
  loadPolicyDraftRemote: vi.fn(),
  savePolicyRemote: vi.fn(),
}));

describe('policyBuilderLifecycle helpers', () => {
  beforeEach(() => {
    vi.mocked(loadPolicyBuilderRemote).mockReset();
    vi.mocked(deletePolicyRemote).mockReset();
    vi.mocked(savePolicyRemote).mockReset();
  });

  it('derives initial load follow-up action', () => {
    const policies = [{ id: 'p-1' }, { id: 'p-2' }] as PolicyRecord[];
    expect(deriveLoadAllFollowUp(policies, null)).toEqual({ kind: 'select-first', policyId: 'p-1' });
    expect(deriveLoadAllFollowUp(policies, 'p-2')).toEqual({ kind: 'none' });
    expect(deriveLoadAllFollowUp([{ id: 'p-2' }] as PolicyRecord[], 'p-1')).toEqual({
      kind: 'select-first',
      policyId: 'p-2',
    });
    expect(deriveLoadAllFollowUp([], null)).toEqual({ kind: 'create' });
  });

  it('normalizes unknown errors to fallback message', () => {
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('boom');
    expect(errorMessage('x', 'fallback')).toBe('fallback');
  });

  it('exposes selected policy state without a legacy selectedId alias', () => {
    let capturedHook: ReturnType<typeof usePolicyBuilder> | null = null;
    const CaptureHook = () => {
      capturedHook = usePolicyBuilder();
      return React.createElement('div');
    };

    renderToStaticMarkup(React.createElement(CaptureHook));

    expect(capturedHook).not.toBeNull();
    expect(capturedHook?.state.selectedPolicyId).toBeNull();
    expect('selectedId' in (capturedHook?.state ?? {})).toBe(false);
  });

  it('tracks selected policy and editor target as separate hook state', () => {
    let capturedStore: ReturnType<typeof usePolicyBuilderState> | null = null;
    const CaptureState = () => {
      capturedStore = usePolicyBuilderState();
      return React.createElement('div');
    };

    renderToStaticMarkup(React.createElement(CaptureState));

    expect(capturedStore).not.toBeNull();
    expect(capturedStore?.selectedPolicyId).toBeNull();
    expect(capturedStore?.editorTargetId).toBeNull();
    expect(capturedStore?.setSelectedPolicyId).not.toBe(capturedStore?.setEditorTargetId);
  });

  it('buildSelectPolicy closes overlay on policy switch', () => {
    const selectedPolicyIds: Array<string | null> = [];
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
    expect(overlayModes).toEqual(['closed']);
    expect(overlaySourceGroupIds).toEqual([null]);
  });

  it('starts overlay closed in hook state and can open edit/create modes', () => {
    let capturedStore: ReturnType<typeof usePolicyBuilderState> | null = null;
    const CaptureState = () => {
      capturedStore = usePolicyBuilderState();
      return React.createElement('div');
    };
    renderToStaticMarkup(React.createElement(CaptureState));

    expect(capturedStore).not.toBeNull();
    expect(capturedStore?.overlayMode).toBe('closed');

    const overlayModes: Array<'closed' | 'create-group' | 'edit-group'> = [];
    const overlaySourceGroupIds: Array<string | null> = [];

    const openSourceGroupEditor = buildOpenSourceGroupEditor({
      setOverlayMode: (value) => {
        overlayModes.push(value);
      },
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });
    const closeSourceGroupEditor = buildCloseSourceGroupEditor({
      setOverlayMode: (value) => {
        overlayModes.push(value);
      },
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });

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
    const deps: PolicyBuilderLifecycleDeps = {
      selectedPolicyId: null,
      editorMode: 'create',
      editorTargetId: null,
      overlayMode: 'closed',
      overlaySourceGroupId: null,
      draft: {} as never,
      integrationNames: new Set<string>(),
      setPolicies: () => undefined,
      setIntegrations: () => undefined,
      setSelectedPolicyId: (value) => selectedPolicyIds.push(value),
      setOverlayMode: () => undefined,
      setOverlaySourceGroupId: () => undefined,
      setLoading: () => undefined,
      setError: () => undefined,
      setDraft: () => undefined,
      setEditorMode: () => undefined,
      setEditorTargetId: () => undefined,
      setSaving: () => undefined,
      setEditorError: () => undefined,
    };

    const loadAll = buildLoadAll(deps, () => undefined);

    await loadAll();

    expect(selectedPolicyIds).toEqual(['p-1']);
  });

  it('resets the editor after deleting the edited policy without clearing the refreshed selection', async () => {
    vi.mocked(deletePolicyRemote).mockResolvedValue(undefined);
    const confirmSpy = vi.fn(() => true);
    vi.stubGlobal('window', { confirm: confirmSpy });

    const selectedPolicyIds: Array<string | null> = [];
    const editorModes: Array<'create' | 'edit'> = [];
    const editorTargetIds: Array<string | null> = [];
    const drafts = new Array<ReturnType<typeof createEmptyPolicyRequest>>();
    const deps: PolicyBuilderLifecycleDeps = {
      selectedPolicyId: 'p-deleted',
      editorMode: 'edit',
      editorTargetId: 'p-deleted',
      overlayMode: 'closed',
      overlaySourceGroupId: null,
      draft: createEmptyPolicyRequest(),
      integrationNames: new Set<string>(),
      setPolicies: () => undefined,
      setIntegrations: () => undefined,
      setSelectedPolicyId: (value) => selectedPolicyIds.push(value),
      setOverlayMode: () => undefined,
      setOverlaySourceGroupId: () => undefined,
      setLoading: () => undefined,
      setError: () => undefined,
      setDraft: (value) => {
        drafts.push(typeof value === 'function' ? value(createEmptyPolicyRequest()) : value);
      },
      setEditorMode: (value) => editorModes.push(value),
      setEditorTargetId: (value) => editorTargetIds.push(value),
      setSaving: () => undefined,
      setEditorError: () => undefined,
    };

    const handleDelete = buildHandleDelete(
      deps,
      async () => {
        selectedPolicyIds.push('p-remaining');
      },
      () => undefined,
    );

    await handleDelete('p-deleted');

    expect(selectedPolicyIds).toEqual(['p-remaining']);
    expect(editorModes).toEqual(['create']);
    expect(editorTargetIds).toEqual([null]);
    expect(drafts).toEqual([createEmptyPolicyRequest()]);
    expect(confirmSpy).toHaveBeenCalledWith('Delete this policy?');

    vi.unstubAllGlobals();
  });

  it('selects the created policy after save without relying on legacy selectedId wiring', async () => {
    vi.mocked(savePolicyRemote).mockResolvedValue({
      editorMode: 'edit',
      editorTargetId: 'p-new',
      selectedPolicyId: 'p-new',
      draft: createEmptyPolicyRequest(),
    });

    const selectedPolicyIds: Array<string | null> = [];
    const deps: PolicyBuilderLifecycleDeps = {
      selectedPolicyId: null,
      editorMode: 'create',
      editorTargetId: null,
      overlayMode: 'closed',
      overlaySourceGroupId: null,
      draft: createEmptyPolicyRequest(),
      integrationNames: new Set<string>(),
      setPolicies: () => undefined,
      setIntegrations: () => undefined,
      setSelectedPolicyId: (value) => selectedPolicyIds.push(value),
      setOverlayMode: () => undefined,
      setOverlaySourceGroupId: () => undefined,
      setLoading: () => undefined,
      setError: () => undefined,
      setDraft: () => undefined,
      setEditorMode: () => undefined,
      setEditorTargetId: () => undefined,
      setSaving: () => undefined,
      setEditorError: () => undefined,
    };

    const handleSave = buildHandleSave(deps, async () => undefined);

    await handleSave();

    expect(selectedPolicyIds).toEqual(['p-new']);
  });
});
