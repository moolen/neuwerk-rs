import React, { useState } from 'react';

import { useAuth } from '../components/auth/AuthProvider';
import { LoginPage } from '../components/auth/LoginPage';
import { AuthenticatedShell } from './AuthenticatedShell';
import { renderAppPage } from './renderPage';
import { useAppNavigation } from './useAppNavigation';

export const AuthenticatedApp: React.FC = () => {
  const { user, loading, logout } = useAuth();
  const { currentPage, navigateTo } = useAppNavigation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: 'var(--bg)' }}>
        <div className="text-lg" style={{ color: 'var(--text-muted)' }}>
          Loading...
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return (
    <AuthenticatedShell
      user={user}
      currentPage={currentPage}
      sidebarCollapsed={sidebarCollapsed}
      mobileNavigationOpen={mobileNavigationOpen}
      onNavigate={navigateTo}
      onToggleSidebar={() => setSidebarCollapsed(!sidebarCollapsed)}
      onToggleMobileNavigation={() => setMobileNavigationOpen((open) => !open)}
      onLogout={logout}
    >
      {renderAppPage(currentPage)}
    </AuthenticatedShell>
  );
};
