import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../../utils/policyModel';
import { PolicyBuilderForm } from './PolicyBuilderForm';

describe('PolicyBuilderForm', () => {
  it('renders separate policy scope and decision surfaces', () => {
    const html = renderToStaticMarkup(
      <PolicyBuilderForm
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
      />,
    );

    expect(html).toContain('Policy scope');
    expect(html).toContain('Decision defaults');
    expect(html).toContain('2xl:grid-cols-[minmax(0,1.24fr)_minmax(15rem,0.76fr)]');
    expect(html).toContain('2xl:sticky 2xl:top-28');
  });
});
