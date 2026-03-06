import React, { useState } from 'react';

import { useAuth } from '../components/auth/AuthProvider';
import { LoginPage } from '../components/auth/LoginPage';
import { Sidebar } from '../components/Sidebar';
import { ThemeToggle } from '../components/ThemeToggle';
import { deriveUserRole } from './authenticatedHelpers';
import { AppHeader } from './AppHeader';
import { renderAppPage } from './renderPage';
import { useAppNavigation } from './useAppNavigation';

export const AuthenticatedApp: React.FC = () => {
  const { user, loading, logout } = useAuth();
  const { currentPage, navigateTo } = useAppNavigation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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

  const userRole = deriveUserRole(user);

  return (
    <div
      className="flex h-screen overflow-hidden"
      style={{
        background: 'var(--bg)',
        fontFamily: "'Plus Jakarta Sans', -apple-system, sans-serif",
        position: 'relative',
        zIndex: 1,
      }}
    >
      <Sidebar
        currentPage={currentPage}
        onNavigate={navigateTo}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        userRole={userRole}
      />

      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <AppHeader user={user} onLogout={logout}>
          <ThemeToggle />
        </AppHeader>

        <div className="flex-1 overflow-auto p-6" style={{ color: 'var(--text)' }}>
          {renderAppPage(currentPage)}
        </div>
      </main>
    </div>
  );
};
