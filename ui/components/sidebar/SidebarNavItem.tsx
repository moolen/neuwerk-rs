import React from 'react';

import type { AppPage, NavItemDefinition } from '../../navigation';
import { PAGE_ICONS } from './constants';
import {
  applySidebarHoverStyle,
  clearSidebarHoverStyle,
  sidebarNavItemBaseStyle,
} from './helpers';

interface SidebarNavItemProps {
  item: NavItemDefinition;
  currentPage: AppPage;
  collapsed: boolean;
  onNavigate: (page: AppPage) => void;
}

export const SidebarNavItem: React.FC<SidebarNavItemProps> = ({
  item,
  currentPage,
  collapsed,
  onNavigate,
}) => {
  const Icon = PAGE_ICONS[item.id];
  const isActive = currentPage === item.id;
  return (
    <button
      onClick={() => onNavigate(item.id)}
      className="w-full flex items-center space-x-3 px-3 py-2.5 text-sm font-medium transition-all"
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
