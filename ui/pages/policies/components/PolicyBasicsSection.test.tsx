import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyPolicyRequest } from '../../../utils/policyModel';
import { PolicyBasicsSection } from './PolicyBasicsSection';

describe('PolicyBasicsSection', () => {
  it('renders enforcement mode and global fallback as side-by-side chip groups', () => {
    const html = renderToStaticMarkup(
      <PolicyBasicsSection
        draft={createEmptyPolicyRequest()}
        setDraft={vi.fn()}
      />,
    );

    expect(html).toContain('sm:grid-cols-2');
    expect(html).toContain('Enforcement Mode');
    expect(html).toContain('Global Fallback Action');
    expect(html).toContain('enforce');
    expect(html).toContain('audit');
    expect(html).toContain('disabled');
    expect(html).toContain('deny');
    expect(html).toContain('allow');
    expect(html).not.toContain('<select');
  });
});
