import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { Sidebar } from './Sidebar';

describe('Sidebar', () => {
  it('renders with full height for the mobile drawer container', () => {
    const html = renderToStaticMarkup(
      <Sidebar
        currentPage="policies"
        onNavigate={() => undefined}
        collapsed={false}
        userRole="admin"
      />,
    );

    expect(html).toContain('h-full');
    expect(html).toContain('w-64');
    expect(html).toContain('Policies');
  });
});
