import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../../utils/policyModel';
import { PolicyBuilderForm } from './PolicyBuilderForm';

describe('PolicyBuilderForm', () => {
  it('renders decision defaults before policy scope without nested glass surfaces', () => {
    const html = renderToStaticMarkup(
      <PolicyBuilderForm
        editorMode="edit"
        editorTargetId="policy-123"
        draft={createEmptyPolicyRequest()}
        integrations={[]}
        setDraft={vi.fn()}
        updateDraft={vi.fn()}
        addGroup={vi.fn()}
        duplicateGroup={vi.fn()}
        moveGroup={vi.fn()}
        deleteGroup={vi.fn()}
        addRule={vi.fn()}
        duplicateRule={vi.fn()}
        moveRule={vi.fn()}
        deleteRule={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    expect(html.indexOf('Decision defaults')).toBeLessThan(html.indexOf('Policy scope'));
    expect(html).toContain('Delete policy');
    expect(html).not.toContain('2xl:grid-cols-[minmax(0,1.24fr)_minmax(15rem,0.76fr)]');
    expect(html).not.toContain('2xl:sticky 2xl:top-28');
    expect(html).not.toContain('rounded-[1.35rem]');
  });
});
