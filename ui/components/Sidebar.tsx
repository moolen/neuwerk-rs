import React from 'react';
import {
  LayoutDashboard,
  Shield,
  Radio,
  Search,
  Globe,
  Key,
  Settings,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: string) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  userRole: 'admin' | 'readonly';
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  collapsed = false,
  onToggleCollapse,
  userRole,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'policies', label: 'Policies', icon: Shield },
    { id: 'wiretap', label: 'Wiretap', icon: Radio },
    { id: 'audit', label: 'Audit', icon: Search },
    { id: 'dns', label: 'DNS Cache', icon: Globe },
    ...(userRole === 'admin' ? [
      { id: 'service-accounts', label: 'Service Accounts', icon: Key }
    ] : []),
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside
      className={`flex flex-col transition-all duration-200 ${collapsed ? 'w-16' : 'w-64'}`}
      style={{
        background: 'var(--bg-glass-strong)',
        backdropFilter: 'blur(20px) saturate(1.5)',
        WebkitBackdropFilter: 'blur(20px) saturate(1.5)',
        borderRight: '1px solid var(--border-glass)',
      }}
    >
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
              <svg viewBox="0 0 24 24" width="20" height="20" fill="white"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
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
            <svg viewBox="0 0 24 24" width="20" height="20" fill="white"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
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

      <nav className="flex-1 p-2 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className="w-full flex items-center space-x-3 px-3 py-2.5 text-sm font-medium transition-all"
              style={{
                borderRadius: 'var(--radius-sm)',
                color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                background: isActive ? 'var(--bg-glass-strong)' : 'transparent',
                border: isActive ? '1px solid var(--border-glass)' : '1px solid transparent',
                boxShadow: isActive ? 'var(--shadow-card)' : 'none',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'var(--bg-glass-subtle)';
                  e.currentTarget.style.color = 'var(--text)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }
              }}
            >
              <Icon className="w-5 h-5 shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>

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
    </aside>
  );
};
