import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi, beforeEach } from 'vitest';

import { ThemeProvider } from '../components/ThemeProvider';
import { AuthenticatedApp } from './AuthenticatedApp';
import { useAuth } from '../components/auth/AuthProvider';
import { useAppNavigation } from './useAppNavigation';
import { renderAppPage } from './renderPage';

vi.mock('../components/auth/AuthProvider', () => ({
  useAuth: vi.fn(),
}));

vi.mock('./useAppNavigation', () => ({
  useAppNavigation: vi.fn(),
}));

vi.mock('./renderPage', () => ({
  renderAppPage: vi.fn(),
}));

describe('AuthenticatedApp', () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({
      user: { sub: 'demo-user', roles: ['admin'] },
      loading: false,
      error: null,
      logout: async () => {},
    });
    vi.mocked(useAppNavigation).mockReturnValue({
      currentPage: 'settings',
      navigateTo: () => {},
    });
    vi.mocked(renderAppPage).mockReturnValue(<div>Rendered page</div>);
  });

  it('renders the shared authenticated shell with the current page label and page content', () => {
    const html = renderToStaticMarkup(
      <ThemeProvider>
        <AuthenticatedApp />
      </ThemeProvider>,
    );

    expect(html).toContain('Settings');
    expect(html).toContain('Rendered page');
    expect(html).toContain('Open navigation');
  });
});
