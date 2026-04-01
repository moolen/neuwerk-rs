import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../utils/policyModel';
import { errorMessage } from './policyBuilderLifecycle';
import { buildHandleSave } from './policyBuilderLifecycleSave';
import {
  loadPolicyBuilderRemote,
  savePolicyRemote,
} from './policyBuilderRemote';
import {
  buildCloseSourceGroupEditor,
  buildLoadAll,
  buildOpenSourceGroupEditor,
} from './policyBuilderLifecycleLoad';
import type { PolicyBuilderLifecycleDeps } from './policyBuilderTypes';
import { usePolicyBuilder } from './usePolicyBuilder';
import { usePolicyBuilderState } from './usePolicyBuilderState';

vi.mock('./policyBuilderRemote', () => ({
  loadPolicyBuilderRemote: vi.fn(),
  loadPolicyDraftRemote: vi.fn(),
  savePolicyRemote: vi.fn(),
  SINGLETON_POLICY_ID: 'singleton',
}));

describe('policyBuilderLifecycle helpers', () => {
  beforeEach(() => {
    vi.mocked(loadPolicyBuilderRemote).mockReset();
    vi.mocked(savePolicyRemote).mockReset();
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

  it('loads the singleton editor state from the singleton policy document', async () => {
    vi.mocked(loadPolicyBuilderRemote).mockResolvedValue({
      draft: createEmptyPolicyRequest(),
      integrations: [],
    });

    const selectedPolicyIds: Array<string | null> = [];
    const editorModes: Array<'create' | 'edit'> = [];
    const editorTargetIds: Array<string | null> = [];
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
      setEditorMode: (value) => editorModes.push(value),
      setEditorTargetId: (value) => editorTargetIds.push(value),
      setSaving: () => undefined,
      setEditorError: () => undefined,
    };

    const loadAll = buildLoadAll(deps);

    await loadAll();

    expect(selectedPolicyIds).toEqual(['singleton']);
    expect(editorModes).toEqual(['edit']);
    expect(editorTargetIds).toEqual(['singleton']);
  });

  it('selects the singleton policy after save without legacy list state wiring', async () => {
    vi.mocked(savePolicyRemote).mockResolvedValue({
      editorMode: 'edit',
      editorTargetId: 'singleton',
      selectedPolicyId: 'singleton',
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

    expect(selectedPolicyIds).toEqual(['singleton']);
  });
});
