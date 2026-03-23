import type { CSSProperties } from 'react';

import { NAV_ITEMS, type AppPage, type NavItemDefinition } from '../../navigation';

type UserRole = 'admin' | 'readonly';

export interface VisibleNavItem extends NavItemDefinition {
  depth: 0 | 1;
  sectionActive: boolean;
}

function isSectionActive(
  currentPage: AppPage,
  parentId: AppPage,
  items: ReadonlyArray<NavItemDefinition>,
): boolean {
  return (
    currentPage === parentId ||
    items.some((item) => item.id === currentPage && item.parentId === parentId)
  );
}

export function filterSidebarNavItems(
  userRole: UserRole,
  currentPage: AppPage,
  items: ReadonlyArray<NavItemDefinition> = NAV_ITEMS,
): VisibleNavItem[] {
  const visible = items.filter((item) => !item.adminOnly || userRole === 'admin');

  return visible.flatMap((item) => {
    if (item.parentId) {
      return [];
    }

    const sectionActive = isSectionActive(currentPage, item.id, visible);
    const parent: VisibleNavItem = { ...item, depth: 0, sectionActive };
    const children = visible
      .filter((candidate) => candidate.parentId === item.id && sectionActive)
      .map((candidate) => ({
        ...candidate,
        depth: 1 as const,
        sectionActive: currentPage === candidate.id,
      }));

    return [parent, ...children];
  });
}

export function shouldRenderSidebarNavItem(item: VisibleNavItem, collapsed: boolean): boolean {
  return !(collapsed && item.depth === 1);
}

export function sidebarNavItemBaseStyle(isActive: boolean): CSSProperties {
  return {
    borderRadius: 'var(--radius-sm)',
    color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
    background: isActive ? 'var(--bg-glass-strong)' : 'transparent',
    border: isActive ? '1px solid var(--border-glass)' : '1px solid transparent',
    boxShadow: isActive ? 'var(--shadow-card)' : 'none',
  };
}

export function applySidebarHoverStyle(target: HTMLButtonElement, isActive: boolean): void {
  if (isActive) return;
  target.style.background = 'var(--bg-glass-subtle)';
  target.style.color = 'var(--text)';
}

export function clearSidebarHoverStyle(target: HTMLButtonElement, isActive: boolean): void {
  if (isActive) return;
  target.style.background = 'transparent';
  target.style.color = 'var(--text-secondary)';
}
