import React from 'react';

import type { AppPage, NavItemDefinition } from '../../navigation';
import { SidebarNavItem } from './SidebarNavItem';

interface SidebarNavProps {
  items: NavItemDefinition[];
  currentPage: AppPage;
  collapsed: boolean;
  onNavigate: (page: AppPage) => void;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  items,
  currentPage,
  collapsed,
  onNavigate,
}) => (
  <nav className="flex-1 p-2 space-y-1">
    {items.map((item) => (
      <SidebarNavItem
        key={item.id}
        item={item}
        currentPage={currentPage}
        collapsed={collapsed}
        onNavigate={onNavigate}
      />
    ))}
  </nav>
);
