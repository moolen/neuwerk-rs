import type { CSSProperties } from 'react';

import { NAV_ITEMS, type NavItemDefinition } from '../../navigation';

type UserRole = 'admin' | 'readonly';

export function filterSidebarNavItems(
  userRole: UserRole,
  items: ReadonlyArray<NavItemDefinition> = NAV_ITEMS,
): NavItemDefinition[] {
  return items.filter((item) => {
    if (item.parentId) {
      return false;
    }
    return !item.adminOnly || userRole === 'admin';
  });
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
