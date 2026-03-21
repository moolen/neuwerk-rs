import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ThreatIntelSettingsStatus } from '../../../types';
import { ThreatAnalysisCard } from './ThreatAnalysisCard';

describe('ThreatAnalysisCard', () => {
  it('renders the current threat analysis state', () => {
    const html = renderToStaticMarkup(
      <ThreatAnalysisCard
        status={
          {
            enabled: false,
            source: 'cluster',
            alert_threshold: 'high',
            baseline_feeds: {
              threatfox: { enabled: true, refresh_interval_secs: 3600 },
              urlhaus: { enabled: true, refresh_interval_secs: 3600 },
              spamhaus_drop: { enabled: true, refresh_interval_secs: 3600 },
            },
            remote_enrichment: { enabled: false },
          } satisfies ThreatIntelSettingsStatus
        }
        loading={false}
        saving={false}
        onToggle={() => {}}
      />,
    );

    expect(html).toContain('Threat Analysis');
    expect(html).toContain('Disabled');
    expect(html).toContain('cluster-wide');
  });
});
