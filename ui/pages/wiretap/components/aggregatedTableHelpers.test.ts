import { describe, expect, it } from 'vitest';

import type { AggregatedFlow } from '../types';
import {
  AGGREGATED_TABLE_COLUMNS,
  formatAggregatedFlowPair,
  formatAggregatedHostname,
} from './aggregatedTableHelpers';

const sampleFlow: AggregatedFlow = {
  key: 'flow-1',
  src_ip: '10.0.0.10',
  dst_ip: '8.8.8.8',
  proto: 17,
  flow_count: 4,
  packets_in: 10,
  packets_out: 12,
  last_seen: 1700000000000,
  hostname: 'dns.google',
};

describe('aggregatedTableHelpers', () => {
  it('keeps canonical table column ordering', () => {
    expect(AGGREGATED_TABLE_COLUMNS).toEqual([
      'Flow Pair',
      'Proto',
      'Flows',
      'Packets In',
      'Packets Out',
      'Hostname',
      'Last Seen',
    ]);
  });

  it('formats flow pair label', () => {
    expect(formatAggregatedFlowPair(sampleFlow)).toBe('10.0.0.10 -> 8.8.8.8');
  });

  it('formats hostname fallbacks', () => {
    expect(formatAggregatedHostname(sampleFlow.hostname)).toBe('dns.google');
    expect(formatAggregatedHostname('   ')).toBe('-');
    expect(formatAggregatedHostname(null)).toBe('-');
  });
});
