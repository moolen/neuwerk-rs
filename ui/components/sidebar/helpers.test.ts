import { describe, expect, it } from 'vitest';

import { NAV_ITEMS, type NavItemDefinition } from '../../navigation';
import { PAGE_ICONS } from './constants';
import {
  applySidebarHoverStyle,
  clearSidebarHoverStyle,
  filterSidebarNavItems,
  sidebarNavItemBaseStyle,
} from './helpers';

describe('sidebar helpers', () => {
  it('filters admin-only nav items for readonly role', () => {
    const items: NavItemDefinition[] = [
      { id: 'dashboard', label: 'Dashboard' },
      { id: 'settings', label: 'Settings', adminOnly: true },
    ];

    expect(filterSidebarNavItems('readonly', items).map((item) => item.id)).toEqual(['dashboard']);
    expect(filterSidebarNavItems('admin', items).map((item) => item.id)).toEqual([
      'dashboard',
      'settings',
    ]);
  });

  it('derives active vs inactive nav item styles', () => {
    expect(sidebarNavItemBaseStyle(true)).toMatchObject({
      color: 'var(--accent)',
      background: 'var(--bg-glass-strong)',
    });
    expect(sidebarNavItemBaseStyle(false)).toMatchObject({
      color: 'var(--text-secondary)',
      background: 'transparent',
    });
  });

  it('applies and clears hover state only for inactive buttons', () => {
    const inactive = { style: { background: '', color: '' } } as HTMLButtonElement;
    applySidebarHoverStyle(inactive, false);
    expect(inactive.style.background).toBe('var(--bg-glass-subtle)');
    expect(inactive.style.color).toBe('var(--text)');

    clearSidebarHoverStyle(inactive, false);
    expect(inactive.style.background).toBe('transparent');
    expect(inactive.style.color).toBe('var(--text-secondary)');

    const active = { style: { background: '', color: '' } } as HTMLButtonElement;
    applySidebarHoverStyle(active, true);
    clearSidebarHoverStyle(active, true);
    expect(active.style.background).toBe('');
    expect(active.style.color).toBe('');
  });

  it('defines an icon for every sidebar item', () => {
    for (const item of NAV_ITEMS) {
      expect(PAGE_ICONS[item.id]).toBeDefined();
    }
  });
});
