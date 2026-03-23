import React from 'react';

import { ThemeToggle } from '../components/ThemeToggle';
import { Sidebar } from '../components/Sidebar';
import type { AuthUser } from '../types';
import type { AppPage } from '../navigation';
import { getPageLabel } from '../navigation';
import { deriveUserRole } from './authenticatedHelpers';
import { AppHeader } from './AppHeader';

interface AuthenticatedShellProps {
  user: AuthUser;
  currentPage: AppPage;
  sidebarCollapsed: boolean;
  mobileNavigationOpen: boolean;
  onNavigate: (page: AppPage) => void;
  onToggleSidebar: () => void;
  onToggleMobileNavigation: () => void;
  onLogout: () => Promise<void>;
  children: React.ReactNode;
}

export const AuthenticatedShell: React.FC<AuthenticatedShellProps> = ({
  user,
  currentPage,
  sidebarCollapsed,
  mobileNavigationOpen,
  onNavigate,
  onToggleSidebar,
  onToggleMobileNavigation,
  onLogout,
  children,
}) => {
  const userRole = deriveUserRole(user);
  const pageLabel = getPageLabel(currentPage);
  const handleNavigate = (page: AppPage) => {
    onNavigate(page);
    if (mobileNavigationOpen) {
      onToggleMobileNavigation();
    }
  };

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
      <div className="hidden lg:flex">
        <Sidebar
          currentPage={currentPage}
          onNavigate={handleNavigate}
          collapsed={sidebarCollapsed}
          onToggleCollapse={onToggleSidebar}
          userRole={userRole}
        />
      </div>

      <div
        aria-label="Mobile navigation"
        className={`lg:hidden fixed inset-0 z-20 ${mobileNavigationOpen ? '' : 'pointer-events-none'}`}
      >
        <div
          className={`absolute inset-0 bg-slate-950/20 transition-opacity ${mobileNavigationOpen ? 'opacity-100' : 'opacity-0'}`}
          onClick={onToggleMobileNavigation}
        />
        <div
          className={`absolute inset-y-0 left-0 w-72 max-w-[85vw] transition-transform ${mobileNavigationOpen ? 'translate-x-0' : '-translate-x-full'}`}
        >
          <Sidebar
            currentPage={currentPage}
            onNavigate={handleNavigate}
            collapsed={false}
            userRole={userRole}
          />
        </div>
      </div>

      <main className="flex-1 flex flex-col h-full overflow-hidden relative min-w-0">
        <AppHeader
          user={user}
          pageLabel={pageLabel}
          onOpenMobileNavigation={onToggleMobileNavigation}
          onLogout={onLogout}
        >
          <ThemeToggle />
        </AppHeader>

        <div className="flex-1 overflow-auto p-4 lg:p-6" style={{ color: 'var(--text)' }}>
          {children}
        </div>
      </main>
    </div>
  );
};
