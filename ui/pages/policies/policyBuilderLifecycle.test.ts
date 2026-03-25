import { describe, expect, it } from 'vitest';

import type { PolicyRecord } from '../../types';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycle';
import { buildCloseSourceGroupEditor, buildOpenSourceGroupEditor, buildSelectPolicy } from './policyBuilderLifecycleLoad';

describe('policyBuilderLifecycle helpers', () => {
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

  it('tracks selected policy separately from editor target', () => {
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

  it('starts overlay closed and can open edit/create modes', () => {
    const overlayModes: Array<'closed' | 'create-group' | 'edit-group'> = [];
    const overlaySourceGroupIds: Array<string | null> = [];

    const openSourceGroupEditor = buildOpenSourceGroupEditor({
      setOverlayMode: (value) =>
        overlayModes.push(value),
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });
    const closeSourceGroupEditor = buildCloseSourceGroupEditor({
      setOverlayMode: (value) =>
        overlayModes.push(value),
      setOverlaySourceGroupId: (value) => overlaySourceGroupIds.push(value),
    });

    closeSourceGroupEditor();
    openSourceGroupEditor(null);
    openSourceGroupEditor('group-1');

    expect(overlayModes).toEqual(['closed', 'create-group', 'edit-group']);
    expect(overlaySourceGroupIds).toEqual([null, null, 'group-1']);
  });
});
