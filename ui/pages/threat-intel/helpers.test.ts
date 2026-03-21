import { describe, expect, it } from 'vitest';

import type { ThreatFinding } from '../../types';
import {
  buildThreatFindingsParams,
  createDefaultThreatFilters,
  filterThreatItems,
} from './helpers';

function threatFinding(overrides: Partial<ThreatFinding> = {}): ThreatFinding {
  return {
    indicator: 'bad.example.com',
    indicator_type: 'hostname',
    observation_layer: 'dns',
    match_source: 'stream',
    source_group: 'workstations',
    severity: 'high',
    confidence: 80,
    feed_hits: [{ feed: 'threatfox', severity: 'high', confidence: 80, reference_url: null, tags: [] }],
    first_seen: 1_700_000_000,
    last_seen: 1_700_000_100,
    count: 3,
    sample_node_ids: ['node-a'],
    alertable: true,
    audit_links: ['dns:none:workstations:bad.example.com'],
    enrichment_status: 'completed',
    ...overrides,
  };
}

describe('threat intel helpers', () => {
  it('defaults to alertable-only threat views and disables that default for audit deep links', () => {
    expect(createDefaultThreatFilters('').alertableOnly).toBe(true);
    expect(createDefaultThreatFilters('?audit_key=dns%3Anone%3Aworkstations%3Abad.example.com')).toMatchObject({
      alertableOnly: false,
      auditKey: 'dns:none:workstations:bad.example.com',
    });
  });

  it('builds server-side threat query params from selected filters', () => {
    const filters = {
      ...createDefaultThreatFilters(''),
      sourceGroup: 'workstations',
      selectedFeeds: ['threatfox'],
      selectedSeverities: ['high', 'critical'],
      selectedLayers: ['dns'],
      timeRange: '24h' as const,
    };

    expect(buildThreatFindingsParams(filters, 1_700_000_000_000)).toEqual({
      alertable: true,
      source_group: ['workstations'],
      feed: ['threatfox'],
      severity: ['high', 'critical'],
      observation_layer: ['dns'],
      since: 1_699_913_600,
      limit: 1000,
    });
  });

  it('applies client-side indicator and audit-link filters', () => {
    const items = [
      threatFinding(),
      threatFinding({
        indicator: '203.0.113.10',
        indicator_type: 'ip',
        audit_links: ['l4:none:workstations:203.0.113.10:443:6:'],
      }),
    ];
    const filters = {
      ...createDefaultThreatFilters('?audit_key=dns%3Anone%3Aworkstations%3Abad.example.com'),
      indicatorQuery: 'bad.example',
    };

    expect(filterThreatItems(items, filters)).toEqual([items[0]]);
  });
});
