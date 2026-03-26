import type { PolicySourceGroupTelemetry } from '../../../types';

export interface PolicyHitsTrendDisplay {
  totalLabel: string;
  direction: 'up' | 'down' | 'flat' | 'none';
  percentChange: number | null;
  trendLabel: string;
}

function formatHitCount(count: number): string {
  return `${count} hit${count === 1 ? '' : 's'}`;
}

export function formatHitsTrend(
  telemetry: PolicySourceGroupTelemetry | null | undefined,
): PolicyHitsTrendDisplay {
  if (!telemetry) {
    return {
      totalLabel: 'No data',
      direction: 'none',
      percentChange: null,
      trendLabel: '--',
    };
  }

  const { current_24h_hits: current, previous_24h_hits: previous } = telemetry;
  if (previous === 0 && current > 0) {
    return {
      totalLabel: formatHitCount(current),
      direction: 'up',
      percentChange: null,
      trendLabel: 'New',
    };
  }

  if (previous === current) {
    return {
      totalLabel: formatHitCount(current),
      direction: current === 0 ? 'none' : 'flat',
      percentChange: 0,
      trendLabel: '0%',
    };
  }

  const delta = current - previous;
  const percentChange = previous > 0 ? Math.round((Math.abs(delta) / previous) * 100) : null;

  return {
    totalLabel: formatHitCount(current),
    direction: delta > 0 ? 'up' : 'down',
    percentChange,
    trendLabel: percentChange === null ? '--' : `${delta > 0 ? '+' : '-'}${percentChange}%`,
  };
}
