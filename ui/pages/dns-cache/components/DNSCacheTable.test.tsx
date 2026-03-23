import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { DNSCacheEntry } from '../../../types';
import { DNSCacheTable } from './DNSCacheTable';

const ENTRY: DNSCacheEntry = {
  hostname: 'db.internal',
  ips: ['10.0.0.10', '10.0.0.11'],
  last_seen: 1_700_000_000,
};

describe('DNSCacheTable', () => {
  it('renders responsive mobile cards alongside desktop table markup', () => {
    const html = renderToStaticMarkup(
      <DNSCacheTable entries={[ENTRY]} loading={false} searchTerm="" />,
    );

    expect(html).toContain('hidden md:block');
    expect(html).toContain('md:hidden');
    expect(html).toContain('Resolved IPs');
    expect(html).toContain('Observed at');
    expect(html).toContain('2 IPs observed');
  });
});
