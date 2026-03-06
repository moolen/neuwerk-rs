import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

import { SIDEBAR_LOGO } from './constants';

interface SidebarHeaderProps {
  collapsed: boolean;
  onToggleCollapse?: () => void;
}

export const SidebarHeader: React.FC<SidebarHeaderProps> = ({ collapsed, onToggleCollapse }) => (
  <div
    className="h-16 flex items-center justify-between px-4"
    style={{ borderBottom: '1px solid var(--border-glass)' }}
  >
    {!collapsed && (
      <div className="flex items-center space-x-3">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{
            background: 'linear-gradient(135deg, var(--accent), var(--purple))',
            boxShadow: '0 4px 12px rgba(79, 110, 247, 0.25)',
          }}
        >
          {SIDEBAR_LOGO}
        </div>
        <span
          className="text-lg font-bold"
          style={{
            background: 'linear-gradient(135deg, var(--accent), var(--purple))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '-0.3px',
          }}
        >
          Neuwerk
        </span>
      </div>
    )}
    {collapsed && (
      <div
        className="w-9 h-9 rounded-lg mx-auto flex items-center justify-center"
        style={{
          background: 'linear-gradient(135deg, var(--accent), var(--purple))',
          boxShadow: '0 4px 12px rgba(79, 110, 247, 0.25)',
        }}
      >
        {SIDEBAR_LOGO}
      </div>
    )}
    {onToggleCollapse && (
      <button
        onClick={onToggleCollapse}
        className="p-1 rounded transition-colors"
        style={{ color: 'var(--text-muted)' }}
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>
    )}
  </div>
);
