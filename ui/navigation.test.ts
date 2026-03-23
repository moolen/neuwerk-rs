import { describe, expect, it } from 'vitest';

import { NAV_ITEMS, getPageFromPathname, getPageLabel } from './navigation';

describe('navigation', () => {
  it('exposes threats as a dedicated app page', () => {
    expect(NAV_ITEMS.find((item) => item.id === 'threats')).toMatchObject({
      id: 'threats',
      label: 'Threats',
    });
    expect(getPageFromPathname('/threats')).toBe('threats');
    expect(getPageFromPathname('/threat-intel')).toBe('threats');
  });

  it('returns app labels for shell and page-frame components', () => {
    expect(getPageLabel('dashboard')).toBe('Dashboard');
    expect(getPageLabel('service-accounts')).toBe('Service Accounts');
  });
});
