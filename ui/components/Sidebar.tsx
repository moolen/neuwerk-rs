import React from 'react';
import type { AppPage } from '../navigation';
import { filterSidebarNavItems } from './sidebar/helpers';
import { SidebarFooter } from './sidebar/SidebarFooter';
import { SidebarHeader } from './sidebar/SidebarHeader';
import { SidebarNav } from './sidebar/SidebarNav';

interface SidebarProps {
  currentPage: AppPage;
  onNavigate: (page: AppPage) => void;
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
  const navItems = filterSidebarNavItems(userRole);

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
      <SidebarHeader collapsed={collapsed} onToggleCollapse={onToggleCollapse} />
      <SidebarNav
        items={navItems}
        currentPage={currentPage}
        collapsed={collapsed}
        onNavigate={onNavigate}
      />
      <SidebarFooter collapsed={collapsed} />
    </aside>
  );
};
