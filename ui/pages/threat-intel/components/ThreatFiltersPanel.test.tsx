import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createDefaultThreatFilters } from '../helpers';
import { ThreatFiltersPanel } from './ThreatFiltersPanel';

describe('ThreatFiltersPanel', () => {
  it('renders the spec-required filter controls', () => {
    const html = renderToStaticMarkup(
      <ThreatFiltersPanel
        filters={createDefaultThreatFilters('')}
        availableFeeds={['threatfox', 'urlhaus']}
        availableSourceGroups={['workstations']}
        loading={false}
        onRefresh={vi.fn()}
        onUpdateFilters={vi.fn()}
      />,
    );

    expect(html).toContain('Hostname or IP');
    expect(html).toContain('Alertable only');
    expect(html).toContain('Source group');
    expect(html).toContain('Observation layer');
    expect(html).toContain('Time range');
    expect(html).toContain('threatfox');
  });
});
