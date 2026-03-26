import { describe, expect, it } from 'vitest';

import { formatHitsTrend } from './policyTelemetryHelpers';

describe('policyTelemetryHelpers', () => {
  it('formats an increasing 24h trend with percentage change', () => {
    expect(
      formatHitsTrend({
        source_group_id: 'apps',
        current_24h_hits: 120,
        previous_24h_hits: 100,
      })
    ).toMatchObject({
      totalLabel: '120 hits',
      direction: 'up',
      percentChange: 20,
      trendLabel: '+20%',
    });
  });

  it('falls back cleanly for a zero-baseline telemetry value', () => {
    expect(
      formatHitsTrend({
        source_group_id: 'apps',
        current_24h_hits: 12,
        previous_24h_hits: 0,
      })
    ).toMatchObject({
      totalLabel: '12 hits',
      direction: 'up',
      percentChange: null,
      trendLabel: 'New',
    });
  });

  it('returns a no-data display when telemetry is missing', () => {
    expect(formatHitsTrend(null)).toMatchObject({
      totalLabel: 'No data',
      direction: 'none',
      percentChange: null,
      trendLabel: '--',
    });
  });
});
