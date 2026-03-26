import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { createEmptyPolicyRequest, createEmptySourceGroup } from '../../../utils/policyModel';
import { PolicySourceGroupEditorOverlay } from './PolicySourceGroupEditorOverlay';
import { ScopedSourceGroupEditor } from './ScopedSourceGroupEditor';

describe('PolicySourceGroupEditorOverlay', () => {
  it('renders an inline overlay surface without modal backdrop markup', () => {
    const html = renderToStaticMarkup(
      <PolicySourceGroupEditorOverlay
        open={true}
        policyLabel="Terraform policy"
        sourceGroupLabel="apps"
        saving={false}
        validationIssueCount={0}
        onClose={() => undefined}
        onSave={() => undefined}
      >
        <div>Scoped editor body</div>
      </PolicySourceGroupEditorOverlay>
    );

    expect(html).toContain('Editing apps');
    expect(html).toContain('Terraform policy');
    expect(html).toContain('data-overlay-surface="inline"');
    expect(html).not.toContain('data-overlay-backdrop');
  });

  it('renders only the targeted source group inside the overlay body', () => {
    const draft = createEmptyPolicyRequest();
    draft.policy.source_groups = [
      createEmptySourceGroup('apps'),
      createEmptySourceGroup('db'),
    ];

    const html = renderToStaticMarkup(
      <ScopedSourceGroupEditor
        sourceGroupId="apps"
        draft={draft}
        integrations={[]}
        updateDraft={() => undefined}
        duplicateGroup={() => undefined}
        moveGroup={() => undefined}
        deleteGroup={() => undefined}
        addRule={() => undefined}
        duplicateRule={() => undefined}
        moveRule={() => undefined}
        deleteRule={() => undefined}
      />
    );

    expect(html).toContain('apps');
    expect(html).not.toContain('db');
    expect(html).toContain('Rule stack');
  });
});
