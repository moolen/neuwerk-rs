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
    draft.name = 'Terraform policy';
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
        overlayMode: 'closed',
        overlaySourceGroupId: null,
        saving: false,
        editorError: null,
        validationIssues: [],
      },
      actions: {
        loadAll: async () => undefined,
        loadEditorForPolicy: async () => undefined,
        selectPolicy: () => undefined,
        openSourceGroupEditor: () => undefined,
        closeSourceGroupEditor: () => undefined,
        handleCreate: () => undefined,
        handleDelete: async () => undefined,
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

    expect(html).toContain('Policy selector');
    expect(html).toContain('Source Identity');
    expect(html).toContain('L3/L4/DNS/DPI Rules');
    expect(html).not.toContain('Snapshot rail');
    expect(html).not.toContain('Policy editor card');
  });

  it('anchors the source-group overlay to the policies page main content area', () => {
    const draft = createEmptyPolicyRequest();
    draft.name = 'Terraform policy';
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
        selectPolicy: () => undefined,
        openSourceGroupEditor: () => undefined,
        closeSourceGroupEditor: () => undefined,
        handleCreate: () => undefined,
        handleDelete: async () => undefined,
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

    expect(html).toContain('data-policies-main-content="true"');
    expect(html).toContain('data-overlay-anchor="policy-main-content"');
  });
});
