import React from 'react';

import type { AppPage } from '../../navigation';
import type { VisibleNavItem } from './helpers';
import { SidebarNavItem } from './SidebarNavItem';

interface SidebarNavProps {
  items: VisibleNavItem[];
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
        depth={item.depth}
        currentPage={currentPage}
        collapsed={collapsed}
        onNavigate={onNavigate}
      />
    ))}
  </nav>
);
