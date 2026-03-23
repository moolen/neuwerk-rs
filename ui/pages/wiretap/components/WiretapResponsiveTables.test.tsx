import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { WiretapEvent } from '../../../types';
import type { AggregatedFlow } from '../types';
import { WiretapAggregatedTable } from './WiretapAggregatedTable';
import { WiretapLiveTable } from './WiretapLiveTable';

const EVENT: WiretapEvent = {
  flow_id: 'flow-1',
  src_ip: '10.0.0.2',
  dst_ip: '1.1.1.1',
  src_port: 53000,
  dst_port: 443,
  proto: 6,
  packets_in: 12,
  packets_out: 8,
  last_seen: 1_700_000_000,
  hostname: 'example.com',
  node_id: 'node-a',
};

const FLOW: AggregatedFlow = {
  key: '10.0.0.2|1.1.1.1|6',
  src_ip: '10.0.0.2',
  dst_ip: '1.1.1.1',
  proto: 6,
  flow_count: 3,
  packets_in: 32,
  packets_out: 20,
  last_seen: 1_700_000_000,
  hostname: 'example.com',
};

describe('wiretap responsive tables', () => {
  it('renders mobile cards for live events alongside desktop table markup', () => {
    const html = renderToStaticMarkup(<WiretapLiveTable events={[EVENT]} />);

    expect(html).toContain('hidden md:block');
    expect(html).toContain('md:hidden');
    expect(html).toContain('Packets in');
    expect(html).toContain('Last seen');
  });

  it('renders mobile cards for aggregated flows alongside desktop table markup', () => {
    const html = renderToStaticMarkup(<WiretapAggregatedTable flows={[FLOW]} />);

    expect(html).toContain('hidden md:block');
    expect(html).toContain('md:hidden');
    expect(html).toContain('Flow count');
    expect(html).toContain('Hostname');
  });
});
