import React from 'react';
import { PanelLeft } from 'lucide-react';

import type { AuthUser } from '../types';
import { authMethodLabel } from './authenticatedHelpers';

interface AppHeaderProps {
  user: AuthUser;
  pageLabel: string;
  onOpenMobileNavigation: () => void;
  onLogout: () => Promise<void>;
  children: React.ReactNode;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  user,
  pageLabel,
  onOpenMobileNavigation,
  onLogout,
  children,
}) => (
  <header
    className="h-16 flex items-center justify-between px-4 lg:px-6 shrink-0 z-10 gap-4"
    style={{
      background: 'var(--bg-glass-strong)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-glass)',
      boxShadow: '0 10px 24px rgba(15, 23, 42, 0.05)',
    }}
  >
    <div className="flex items-center gap-3 min-w-0">
      <button
        type="button"
        aria-label="Open navigation"
        onClick={onOpenMobileNavigation}
        className="lg:hidden p-2 rounded-lg transition-colors"
        style={{
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <PanelLeft className="w-4 h-4" />
      </button>

      <div
        data-testid="app-header-page-label"
        className="lg:hidden text-sm font-semibold truncate"
        style={{ color: 'var(--text)' }}
      >
        {pageLabel}
      </div>

      <div
        className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full text-sm"
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
        <span style={{ color: 'var(--text)' }} className="font-medium text-sm">
          {user.sub}
        </span>
        <span style={{ color: 'var(--text-muted)' }} className="text-xs">
          {authMethodLabel(user)}
        </span>
      </div>
    </div>
    <div className="flex items-center space-x-2 lg:space-x-3 shrink-0">
      {children}
      <button
        onClick={() => {
          void onLogout();
        }}
        className="text-xs sm:text-sm font-medium px-2.5 sm:px-3 py-1.5 rounded-lg transition-colors"
        style={{
          color: 'var(--text-muted)',
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
        }}
        onMouseEnter={(event) => {
          event.currentTarget.style.color = 'var(--red)';
          event.currentTarget.style.borderColor = 'var(--red-border)';
          event.currentTarget.style.background = 'var(--red-bg)';
        }}
        onMouseLeave={(event) => {
          event.currentTarget.style.color = 'var(--text-muted)';
          event.currentTarget.style.borderColor = 'var(--border-subtle)';
          event.currentTarget.style.background = 'var(--bg-input)';
        }}
      >
        Logout
      </button>
    </div>
  </header>
);
