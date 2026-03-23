import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ThemeProvider } from '../components/ThemeProvider';
import type { AuthUser } from '../types';
import { AuthenticatedShell } from './AuthenticatedShell';

const USER: AuthUser = {
  sub: 'demo-user',
  roles: ['admin'],
};

describe('AuthenticatedShell', () => {
  it('renders the current page label and an open mobile navigation drawer', () => {
    const html = renderToStaticMarkup(
      <ThemeProvider>
        <AuthenticatedShell
          user={USER}
          currentPage="policies"
          sidebarCollapsed={false}
          mobileNavigationOpen={true}
          onNavigate={() => {}}
          onToggleSidebar={() => {}}
          onToggleMobileNavigation={() => {}}
          onLogout={async () => {}}
        >
          <div>Policy body</div>
        </AuthenticatedShell>
      </ThemeProvider>,
    );

    expect(html).toContain('Policies');
    expect(html).toContain('Policy body');
    expect(html).toContain('Mobile navigation');
    expect(html).toContain('Open navigation');
    expect(html).toContain('fixed inset-0');
  });

  it('uses the child label in the shell header', () => {
    const html = renderToStaticMarkup(
      <ThemeProvider>
        <AuthenticatedShell
          user={USER}
          currentPage="threat-findings"
          sidebarCollapsed={false}
          mobileNavigationOpen={false}
          onNavigate={() => {}}
          onToggleSidebar={() => {}}
          onToggleMobileNavigation={() => {}}
          onLogout={async () => {}}
        >
          <div>Threat details body</div>
        </AuthenticatedShell>
      </ThemeProvider>,
    );

    expect(html).toMatch(/data-testid="app-header-page-label"[^>]*>Findings</);
  });
});
