import { describe, expect, it } from 'vitest';

import type { WiretapEvent } from '../../types';
import {
  defaultWiretapFilters,
  flushBufferedEvents,
  upsertWiretapEvent,
} from './state';

function event(id: string, lastSeen: number): WiretapEvent {
  return {
    flow_id: id,
    src_ip: '10.0.0.1',
    dst_ip: '10.0.0.2',
    src_port: 1000,
    dst_port: 443,
    proto: 6,
    packets_in: 1,
    packets_out: 1,
    bytes_in: 10,
    bytes_out: 20,
    first_seen: lastSeen - 10,
    last_seen: lastSeen,
    event_type: 'flow',
  };
}

describe('wiretap state helpers', () => {
  it('returns empty default filters', () => {
    expect(defaultWiretapFilters()).toEqual({
      source_ip: '',
      dest_ip: '',
      hostname: '',
      port: '',
    });
  });

  it('upserts event by flow id and prepends new events', () => {
    const base = [event('a', 1), event('b', 2)];
    const replaced = upsertWiretapEvent(base, { ...event('a', 3), packets_in: 9 }, 500);
    expect(replaced).toHaveLength(2);
    expect(replaced[0].flow_id).toBe('a');
    expect(replaced[0].packets_in).toBe(9);

    const added = upsertWiretapEvent(base, event('c', 4), 500);
    expect(added[0].flow_id).toBe('c');
    expect(added).toHaveLength(3);
  });

  it('enforces max event cap and flushes buffered events first', () => {
    const base = [event('a', 1), event('b', 2), event('c', 3)];
    const capped = upsertWiretapEvent(base, event('d', 4), 3);
    expect(capped.map((item) => item.flow_id)).toEqual(['d', 'a', 'b']);

    const flushed = flushBufferedEvents([event('current', 1)], [event('buf1', 2), event('buf2', 3)], 2);
    expect(flushed.map((item) => item.flow_id)).toEqual(['buf1', 'buf2']);
  });
});
