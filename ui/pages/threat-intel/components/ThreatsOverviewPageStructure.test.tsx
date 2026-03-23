import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { ThreatsOverviewPage } from '../../ThreatsOverviewPage';
import { useThreatOverviewPage } from '../useThreatOverviewPage';

vi.mock('../useThreatOverviewPage', () => ({
  useThreatOverviewPage: vi.fn(),
}));

describe('ThreatsOverviewPage structure', () => {
  it('renders feed freshness as the threat landing page', () => {
    vi.mocked(useThreatOverviewPage).mockReturnValue({
      feedStatus: { snapshot_version: 9, feeds: [], disabled: false },
      disabled: false,
      partial: true,
      nodeErrors: [{ node_id: 'node-b', error: 'timeout' }],
      nodesQueried: 3,
      nodesResponded: 2,
      findingsCount: 12,
      loading: false,
      error: null,
      refresh: async () => {},
    });

    const html = renderToStaticMarkup(<ThreatsOverviewPage />);
    expect(html).toContain('Threats');
    expect(html).toContain('Feed Freshness');
    expect(html).toContain('Visible findings');
    expect(html).not.toContain('Investigate');
    expect(html).not.toContain('Add silence');
  });
});
