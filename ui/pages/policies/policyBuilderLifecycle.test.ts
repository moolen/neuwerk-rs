import React from 'react';
import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
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
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';
import { usePolicyBuilderState } from './usePolicyBuilderState';

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

  it('removes legacy selectedId lifecycle deps and wiring', () => {
    const lifecycleTypesSource = readFileSync(new URL('./policyBuilderTypes.ts', import.meta.url), 'utf8');
    const policyBuilderHookSource = readFileSync(new URL('./usePolicyBuilder.ts', import.meta.url), 'utf8');

    expect(lifecycleTypesSource).not.toContain('selectedId: string | null;');
    expect(lifecycleTypesSource).not.toContain('setSelectedId: Dispatch<SetStateAction<string | null>>;');
    expect(policyBuilderHookSource).not.toContain('setSelectedId: setSelectedPolicyId');
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
    const selectedIds: Array<string | null> = [];
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

    const loadAll = buildLoadAll(
      deps,
      async () => undefined,
      () => undefined,
    );

    await loadAll();

    expect(selectedPolicyIds).toEqual(['p-1']);
  });
});
