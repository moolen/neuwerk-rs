import React from 'react';

interface SidebarFooterProps {
  collapsed: boolean;
}

export const SidebarFooter: React.FC<SidebarFooterProps> = ({ collapsed }) => (
  <div className="p-3" style={{ borderTop: '1px solid var(--border-glass)' }}>
    {!collapsed && (
      <div
        className="px-3 py-2 rounded-lg flex items-center gap-2"
        style={{
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-glass)',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div
          className="w-2 h-2 rounded-full"
          style={{
            background: 'var(--green)',
            boxShadow: '0 0 8px rgba(16, 185, 129, 0.4)',
          }}
        />
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          DNS-aware egress firewall
        </span>
      </div>
    )}
  </div>
);
