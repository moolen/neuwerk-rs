import { describe, expect, it } from 'vitest';

import type { WiretapEvent } from '../../../types';
import {
  formatLiveFlowLabel,
  formatLiveHostname,
  LIVE_TABLE_COLUMNS,
} from './liveTableHelpers';

const sampleEvent: WiretapEvent = {
  flow_id: 'flow-1',
  src_ip: '10.0.0.12',
  dst_ip: '1.1.1.1',
  src_port: 53000,
  dst_port: 443,
  proto: 6,
  packets_in: 11,
  packets_out: 13,
  last_seen: 1700000000000,
  hostname: 'example.com',
  node_id: 'node-a',
};

describe('liveTableHelpers', () => {
  it('keeps canonical live-table column ordering', () => {
    expect(LIVE_TABLE_COLUMNS).toEqual([
      'Flow',
      'Proto',
      'Packets In',
      'Packets Out',
      'Hostname',
      'Last Seen',
    ]);
  });

  it('formats flow labels', () => {
    expect(formatLiveFlowLabel(sampleEvent)).toBe('10.0.0.12:53000 -> 1.1.1.1:443');
  });

  it('formats hostname fallbacks', () => {
    expect(formatLiveHostname(sampleEvent.hostname)).toBe('example.com');
    expect(formatLiveHostname('   ')).toBe('-');
    expect(formatLiveHostname(null)).toBe('-');
  });
});
