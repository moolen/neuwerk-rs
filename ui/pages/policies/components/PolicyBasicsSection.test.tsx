import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../../utils/policyModel';
import { PolicyBasicsSection } from './PolicyBasicsSection';

describe('PolicyBasicsSection', () => {
  it('renders singleton policy context and global fallback controls', () => {
    const html = renderToStaticMarkup(
      <PolicyBasicsSection
        draft={createEmptyPolicyRequest()}
        setDraft={vi.fn()}
      />,
    );

    expect(html).toContain('sm:grid-cols-2');
    expect(html).toContain('Always-active singleton policy');
    expect(html).toContain('Global Fallback Action');
    expect(html).toContain('deny');
    expect(html).toContain('allow');
    expect(html).not.toContain('<select');
  });
});
