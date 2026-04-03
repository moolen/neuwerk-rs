import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest, createEmptySourceGroup } from '../utils/policyModel';
import { PoliciesPage } from './PoliciesPage';
import { usePolicyBuilder } from './policies/usePolicyBuilder';

vi.mock('./policies/usePolicyBuilder', () => ({
  usePolicyBuilder: vi.fn(),
}));

describe('PoliciesPage', () => {
  beforeEach(() => {
    const draft = createEmptyPolicyRequest();
    draft.policy.source_groups = [createEmptySourceGroup('apps')];
    draft.policy.source_groups[0].mode = 'audit';

    vi.mocked(usePolicyBuilder).mockReturnValue({
      state: {
        policies: [
          {
            id: 'policy-1',
            created_at: '2026-03-25T10:00:00Z',
            name: 'Terraform policy',
            mode: 'enforce',
            policy: draft.policy,
          },
        ],
        integrations: [],
        selectedPolicyId: 'policy-1',
        loading: false,
        error: null,
        draft,
        editorMode: 'edit',
        editorTargetId: 'policy-1',
        overlayMode: 'closed',
        overlaySourceGroupId: null,
        saving: false,
        editorError: null,
        validationIssues: [],
      },
      actions: {
        loadAll: async () => undefined,
        loadEditorForPolicy: async () => undefined,
        openSourceGroupEditor: () => undefined,
        closeSourceGroupEditor: () => undefined,
        handleSave: async () => undefined,
        updateDraft: () => undefined,
        setDraft: () => draft,
        addGroup: () => undefined,
        duplicateGroup: () => undefined,
        moveGroup: () => undefined,
        deleteGroup: () => undefined,
        addRule: () => undefined,
        duplicateRule: () => undefined,
        moveRule: () => undefined,
        deleteRule: () => undefined,
      },
    });
  });

  it('renders the selector and source-group table instead of the old split editor layout', () => {
    const html = renderToStaticMarkup(<PoliciesPage />);

    expect(html).toContain('Policy defaults');
    expect(html).toContain('Global Fallback Action');
    expect(html).not.toContain('Policy selector');
    expect(html).not.toContain('Delete policy');
    expect(html).not.toContain('Open policy');
    expect(html).toContain('Source Identity');
    expect(html).toContain('L3/L4/DNS/DPI Rules');
    expect(html).toContain('Audit');
    expect(html).not.toContain('Snapshot rail');
    expect(html).toContain('Save');
  });

  it('anchors the source-group overlay to the full policies page shell', () => {
    const draft = createEmptyPolicyRequest();
    draft.policy.source_groups = [createEmptySourceGroup('apps')];

    vi.mocked(usePolicyBuilder).mockReturnValue({
      state: {
        policies: [
          {
            id: 'policy-1',
            created_at: '2026-03-25T10:00:00Z',
            name: 'Terraform policy',
            mode: 'enforce',
            policy: draft.policy,
          },
        ],
        integrations: [],
        selectedPolicyId: 'policy-1',
        loading: false,
        error: null,
        draft,
        editorMode: 'edit',
        editorTargetId: 'policy-1',
        overlayMode: 'edit-group',
        overlaySourceGroupId: 'apps',
        saving: false,
        editorError: null,
        validationIssues: [],
      },
      actions: {
        loadAll: async () => undefined,
        loadEditorForPolicy: async () => undefined,
        openSourceGroupEditor: () => undefined,
        closeSourceGroupEditor: () => undefined,
        handleSave: async () => undefined,
        updateDraft: () => undefined,
        setDraft: () => draft,
        addGroup: () => undefined,
        duplicateGroup: () => undefined,
        moveGroup: () => undefined,
        deleteGroup: () => undefined,
        addRule: () => undefined,
        duplicateRule: () => undefined,
        moveRule: () => undefined,
        deleteRule: () => undefined,
      },
    });

    const html = renderToStaticMarkup(<PoliciesPage />);

    expect(html).toContain('data-policies-page-root="true"');
    expect(html).toContain('data-overlay-anchor="policies-page-root"');
    expect(html).not.toContain('data-overlay-anchor="policy-main-content"');
  });

  it('renders singleton policy copy without policy lifecycle controls', () => {
    const draft = createEmptyPolicyRequest();

    vi.mocked(usePolicyBuilder).mockReturnValue({
      state: {
        policies: [],
        integrations: [],
        selectedPolicyId: null,
        loading: false,
        error: null,
        draft,
        editorMode: 'create',
        editorTargetId: null,
        overlayMode: 'closed',
        overlaySourceGroupId: null,
        saving: false,
        editorError: null,
        validationIssues: [],
      },
      actions: {
        loadAll: async () => undefined,
        loadEditorForPolicy: async () => undefined,
        openSourceGroupEditor: () => undefined,
        closeSourceGroupEditor: () => undefined,
        handleSave: async () => undefined,
        updateDraft: () => undefined,
        setDraft: () => draft,
        addGroup: () => undefined,
        duplicateGroup: () => undefined,
        moveGroup: () => undefined,
        deleteGroup: () => undefined,
        addRule: () => undefined,
        duplicateRule: () => undefined,
        moveRule: () => undefined,
        deleteRule: () => undefined,
      },
    });

    const html = renderToStaticMarkup(<PoliciesPage />);

    expect(html).toContain('Global Fallback Action');
    expect(html).toContain('Source groups');
    expect(html).not.toContain('Always-active singleton policy');
    expect(html).not.toContain('Neuwerk now provisions one canonical policy document');
    expect(html).not.toContain('New Policy');
    expect(html).not.toContain('Refresh');
    expect(html).toContain('Save');
  });
});
