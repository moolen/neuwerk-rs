import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ThreatFinding } from '../../../types';
import { ThreatFindingsPage } from '../../ThreatFindingsPage';
import { createDefaultThreatFilters } from '../helpers';
import { useThreatFindingsPage } from '../useThreatFindingsPage';

vi.mock('../useThreatFindingsPage', () => ({
  useThreatFindingsPage: vi.fn(),
}));

function threatFindingFixture(overrides: Partial<ThreatFinding> = {}): ThreatFinding {
  return {
    indicator: 'bad.example.com',
    indicator_type: 'hostname',
    observation_layer: 'dns',
    match_source: 'stream',
    source_group: 'branch-a',
    severity: 'high',
    confidence: 90,
    feed_hits: [{ feed: 'threatfox', severity: 'high', confidence: 90, reference_url: null, tags: [] }],
    first_seen: 1_700_000_000,
    last_seen: 1_700_000_100,
    count: 2,
    sample_node_ids: ['node-a'],
    alertable: true,
    audit_links: ['audit-1'],
    enrichment_status: 'completed',
    ...overrides,
  };
}

describe('ThreatFindingsPage structure', () => {
  it('renders the investigation workspace without feed cards or silence management', () => {
    vi.mocked(useThreatFindingsPage).mockReturnValue({
      items: [threatFindingFixture()],
      rawItems: [threatFindingFixture()],
      filters: { ...createDefaultThreatFilters(''), auditKey: 'audit-1' },
      availableFeeds: ['threatfox'],
      availableSourceGroups: ['branch-a'],
      loading: false,
      error: null,
      partial: false,
      nodeErrors: [],
      nodesQueried: 2,
      nodesResponded: 2,
      disabled: false,
      silenceSaving: false,
      load: async () => {},
      updateFilters: () => {},
      createSilence: async () => {},
    });

    const html = renderToStaticMarkup(<ThreatFindingsPage />);
    expect(html).toContain('Findings');
    expect(html).toContain('Investigate');
    expect(html).toContain('Audit-linked view');
    expect(html).not.toContain('Feed Freshness');
    expect(html).not.toContain('Silences');
  });
});
