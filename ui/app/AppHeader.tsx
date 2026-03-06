import React from 'react';

import type { AuthUser } from '../types';
import { authMethodLabel } from './authenticatedHelpers';

interface AppHeaderProps {
  user: AuthUser;
  onLogout: () => Promise<void>;
  children: React.ReactNode;
}

export const AppHeader: React.FC<AppHeaderProps> = ({ user, onLogout, children }) => (
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
        <span style={{ color: 'var(--text)' }} className="font-medium text-sm">
          {user.sub}
        </span>
        <span style={{ color: 'var(--text-muted)' }} className="text-xs">
          {authMethodLabel(user)}
        </span>
      </div>
    </div>
    <div className="flex items-center space-x-3">
      {children}
      <button
        onClick={() => {
          void onLogout();
        }}
        className="text-sm font-medium px-3 py-1.5 rounded-lg transition-colors"
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
