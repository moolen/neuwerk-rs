import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptySourceGroup } from '../../../utils/policyModel';
import { SourceGroupHeaderFields } from './SourceGroupHeaderFields';

describe('SourceGroupHeaderFields', () => {
  it('renders source-group mode controls alongside fallback controls', () => {
    const group = createEmptySourceGroup('apps');
    const html = renderToStaticMarkup(
      <SourceGroupHeaderFields group={group} groupIndex={0} updateDraft={vi.fn()} />,
    );

    expect(html).toContain('Mode');
    expect(html).toContain('Audit');
    expect(html).toContain('Enforce');
    expect(html).toContain('rules can override it');
  });
});
