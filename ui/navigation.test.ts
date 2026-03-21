import { describe, expect, it } from 'vitest';

import { NAV_ITEMS, getPageFromPathname } from './navigation';

describe('navigation', () => {
  it('exposes threats as a dedicated app page', () => {
    expect(NAV_ITEMS.find((item) => item.id === 'threats')).toMatchObject({
      id: 'threats',
      label: 'Threats',
    });
    expect(getPageFromPathname('/threats')).toBe('threats');
    expect(getPageFromPathname('/threat-intel')).toBe('threats');
  });
});
