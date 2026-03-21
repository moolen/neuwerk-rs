import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ThreatFinding } from '../../../types';
import { ThreatFindingsTable } from './ThreatFindingsTable';

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
    sample_node_ids: ['node-a', 'node-b'],
    alertable: true,
    audit_links: ['dns:none:workstations:bad.example.com'],
    enrichment_status: 'completed',
    ...overrides,
  };
}

describe('ThreatFindingsTable', () => {
  it('renders the spec-required columns and row details', () => {
    const html = renderToStaticMarkup(
      <ThreatFindingsTable
        items={[threatFinding()]}
        loading={false}
        onSilenceExact={() => {}}
        onSilenceHostnameRegex={() => {}}
      />,
    );

    expect(html).toContain('First Seen');
    expect(html).toContain('Sample Nodes');
    expect(html).toContain('Enrichment');
    expect(html).toContain('bad.example.com');
    expect(html).toContain('node-a');
    expect(html).toContain('completed');
  });

  it('renders exact and hostname-regex silence actions for hostname findings', () => {
    const html = renderToStaticMarkup(
      <ThreatFindingsTable
        items={[threatFinding({ indicator_type: 'hostname' })]}
        loading={false}
        onSilenceExact={() => {}}
        onSilenceHostnameRegex={() => {}}
      />,
    );

    expect(html).toContain('Silence exact indicator');
    expect(html).toContain('Silence hostname regex');
  });

  it('renders only the exact silence action for ip findings', () => {
    const html = renderToStaticMarkup(
      <ThreatFindingsTable
        items={[threatFinding({ indicator: '203.0.113.10', indicator_type: 'ip' })]}
        loading={false}
        onSilenceExact={() => {}}
        onSilenceHostnameRegex={() => {}}
      />,
    );

    expect(html).toContain('Silence exact indicator');
    expect(html).not.toContain('Silence hostname regex');
  });
});
