import React from 'react';

import type { AppPage } from '../../navigation';
import { PAGE_ICONS } from './constants';
import {
  applySidebarHoverStyle,
  clearSidebarHoverStyle,
  shouldRenderSidebarNavItem,
  sidebarNavItemBaseStyle,
  type VisibleNavItem,
} from './helpers';

interface SidebarNavItemProps {
  item: VisibleNavItem;
  depth: 0 | 1;
  currentPage: AppPage;
  collapsed: boolean;
  onNavigate: (page: AppPage) => void;
}

export const SidebarNavItem: React.FC<SidebarNavItemProps> = ({
  item,
  depth,
  currentPage,
  collapsed,
  onNavigate,
}) => {
  if (!shouldRenderSidebarNavItem(item, collapsed)) {
    return null;
  }

  const Icon = PAGE_ICONS[item.id];
  const isActive = currentPage === item.id || (depth === 0 && item.sectionActive);
  const paddingClass = depth === 1 ? (collapsed ? '' : 'pl-10') : '';
  return (
    <button
      onClick={() => onNavigate(item.id)}
      className={`w-full flex items-center space-x-3 px-3 py-2.5 text-sm font-medium transition-all ${paddingClass}`}
      style={sidebarNavItemBaseStyle(isActive)}
      onMouseEnter={(event) => {
        applySidebarHoverStyle(event.currentTarget, isActive);
      }}
      onMouseLeave={(event) => {
        clearSidebarHoverStyle(event.currentTarget, isActive);
      }}
    >
      <Icon className="w-5 h-5 shrink-0" />
      {!collapsed && <span>{item.label}</span>}
    </button>
  );
};
