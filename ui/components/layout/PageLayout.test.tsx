import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PageLayout } from './PageLayout';

describe('PageLayout', () => {
  it('renders the shared title, description, actions, and content structure', () => {
    const html = renderToStaticMarkup(
      <PageLayout
        title="Policies"
        description="Form-driven policy builder."
        actions={<button type="button">New</button>}
      >
        <div>Page body</div>
      </PageLayout>,
    );

    expect(html).toContain('Policies');
    expect(html).toContain('Form-driven policy builder.');
    expect(html).toContain('New');
    expect(html).toContain('Page body');
    expect(html).toContain('lg:flex-row');
  });
});
