import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../../utils/policyModel';
import { PolicyBasicsSection } from './PolicyBasicsSection';

describe('PolicyBasicsSection', () => {
  it('renders global fallback controls without the singleton policy info card', () => {
    const html = renderToStaticMarkup(
      <PolicyBasicsSection
        draft={createEmptyPolicyRequest()}
        setDraft={vi.fn()}
      />,
    );

    expect(html).toContain('Global Fallback Action');
    expect(html).toContain('Effective decision path');
    expect(html).toContain('deny');
    expect(html).toContain('allow');
    expect(html).not.toContain('Always-active singleton policy');
    expect(html).not.toContain('<select');
  });
});
