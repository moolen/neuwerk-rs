import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { ThemeProvider } from './components/ThemeProvider';
import { ThemeToggle } from './components/ThemeToggle';
import { Dashboard } from './pages/Dashboard';
import { PoliciesPage } from './pages/PoliciesPage';
import { WiretapPage } from './pages/WiretapPage';
import { AuditPage } from './pages/AuditPage';
import { DNSCachePage } from './pages/DNSCachePage';
import { ServiceAccountsPage } from './pages/ServiceAccountsPage';
import { SettingsPage } from './pages/SettingsPage';
import { AuthProvider, useAuth } from './components/auth/AuthProvider';
import { LoginPage } from './components/auth/LoginPage';

const validPages = ['dashboard', 'policies', 'wiretap', 'audit', 'dns', 'service-accounts', 'settings'];

function getPageFromPath(): string {
  const path = window.location.pathname.replace(/^\//, '').replace(/\/$/, '');
  if (path === '' || !validPages.includes(path)) {
    return 'dashboard';
  }
  return path;
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AuthenticatedApp />
      </AuthProvider>
    </ThemeProvider>
  );
}

function AuthenticatedApp() {
  const { user, loading, logout } = useAuth();
  const [currentPage, setCurrentPage] = useState(getPageFromPath);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const navigateTo = useCallback((page: string) => {
    setCurrentPage(page);
    const newPath = page === 'dashboard' ? '/' : `/${page}`;
    window.history.pushState({ page }, '', newPath);
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPage(getPageFromPath());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />;
      case 'policies':
        return <PoliciesPage />;
      case 'wiretap':
        return <WiretapPage />;
      case 'audit':
        return <AuditPage />;
      case 'dns':
        return <DNSCachePage />;
      case 'service-accounts':
        return <ServiceAccountsPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <Dashboard />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: 'var(--bg)' }}>
        <div className="text-lg" style={{ color: 'var(--text-muted)' }}>Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  const userRole = user.roles.includes('readonly') ? 'readonly' : 'admin';

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg)', fontFamily: "'Plus Jakarta Sans', -apple-system, sans-serif", position: 'relative', zIndex: 1 }}>
      <Sidebar
        currentPage={currentPage}
        onNavigate={navigateTo}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        userRole={userRole}
      />

      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <header
          className="h-16 flex items-center justify-between px-6 shrink-0 z-10"
          style={{
            background: 'var(--bg-glass)',
            backdropFilter: 'blur(16px)',
            WebkitBackdropFilter: 'blur(16px)',
            borderBottom: '1px solid var(--border-glass)',
          }}
        >
          <div className="flex items-center space-x-3 text-sm">
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-full"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center text-white text-xs font-bold"
                style={{ background: 'linear-gradient(135deg, var(--accent), var(--purple))' }}
              >
                {user.sub?.charAt(0).toUpperCase() || 'U'}
              </div>
              <span style={{ color: 'var(--text)' }} className="font-medium text-sm">{user.sub}</span>
              <span style={{ color: 'var(--text-muted)' }} className="text-xs">
                {user.sa_id ? 'service account' : 'jwt'}
              </span>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <ThemeToggle />
            <button
              onClick={logout}
              className="text-sm font-medium px-3 py-1.5 rounded-lg transition-colors"
              style={{
                color: 'var(--text-muted)',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = 'var(--red)';
                e.currentTarget.style.borderColor = 'var(--red-border)';
                e.currentTarget.style.background = 'var(--red-bg)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--text-muted)';
                e.currentTarget.style.borderColor = 'var(--border-subtle)';
                e.currentTarget.style.background = 'var(--bg-input)';
              }}
            >
              Logout
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-auto p-6" style={{ color: 'var(--text)' }}>
          {renderPage()}
        </div>
      </main>
    </div>
  );
}
