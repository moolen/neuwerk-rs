import { describe, expect, it } from 'vitest';

import {
  NAV_ITEMS,
  getPageFromPathname,
  getPageLabel,
  pageToPath,
} from './navigation';

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

  it('maps threat child routes to distinct app pages', () => {
    expect(getPageFromPathname('/threats')).toBe('threats');
    expect(getPageFromPathname('/threats/findings')).toBe('threat-findings');
    expect(getPageFromPathname('/threats/silences')).toBe('threat-silences');
    expect(getPageFromPathname('/threat-intel')).toBe('threats');
  });

  it('renders labels and paths for threat child pages', () => {
    expect(getPageLabel('threat-findings')).toBe('Findings');
    expect(getPageLabel('threat-silences')).toBe('Silences');
    expect(pageToPath('threat-findings')).toBe('/threats/findings');
    expect(pageToPath('threat-silences')).toBe('/threats/silences');
  });
});
