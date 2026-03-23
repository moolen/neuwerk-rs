import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DNSCachePage } from '../../DNSCachePage';
import { useDNSCachePage } from '../useDNSCachePage';

vi.mock('../useDNSCachePage', () => ({
  useDNSCachePage: vi.fn(),
}));

describe('DNSCachePage structure', () => {
  beforeEach(() => {
    vi.mocked(useDNSCachePage).mockReturnValue({
      entries: [
        {
          hostname: 'api.internal',
          ips: ['10.0.0.12'],
          last_seen: 1_700_000_000,
        },
        {
          hostname: 'db.internal',
          ips: ['10.0.0.10', '10.0.0.11'],
          last_seen: 1_700_000_100,
        },
      ],
      filteredEntries: [
        {
          hostname: 'api.internal',
          ips: ['10.0.0.12'],
          last_seen: 1_700_000_000,
        },
        {
          hostname: 'db.internal',
          ips: ['10.0.0.10', '10.0.0.11'],
          last_seen: 1_700_000_100,
        },
      ],
      loading: false,
      error: null,
      searchTerm: '',
      setSearchTerm: () => {},
      refresh: async () => {},
    });
  });

  it('renders a cache posture summary, operator controls, and observed mappings surface', () => {
    const html = renderToStaticMarkup(<DNSCachePage />);

    expect(html).toContain('Cache posture');
    expect(html).toContain('2 hostnames');
    expect(html).toContain('3 resolved IPs');
    expect(html).toContain('Search and refresh');
    expect(html).toContain('Observed mappings');
  });
});
