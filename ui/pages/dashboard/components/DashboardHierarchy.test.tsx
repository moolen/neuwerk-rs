import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { StatsResponse } from '../../../types';
import { DashboardStatsView } from './DashboardStatsView';

const stats: StatsResponse = {
  dataplane: {
    active_flows: 4821,
    active_nat_entries: 1203,
    nat_port_utilization: 0.128,
    packets: {
      allow: 240001,
      deny: 1182,
      pending_tls: 27,
    },
    bytes: {
      allow: 18000000,
      deny: 240000,
      pending_tls: 12000,
    },
    flows_opened: 8921,
    flows_closed: 4100,
    ipv4_fragments_dropped: 12,
    ipv4_ttl_exceeded: 4,
  },
  dns: {
    queries_allow: 12991,
    queries_deny: 842,
    nxdomain_policy: 91,
    nxdomain_upstream: 44,
  },
  tls: {
    allow: 1880,
    deny: 18,
  },
  dhcp: {
    lease_active: true,
    lease_expiry_epoch: 1700000000,
  },
  cluster: {
    is_leader: true,
    current_term: 7600,
    last_log_index: 12000,
    last_applied: 11992,
    node_count: 3,
    follower_count: 2,
    followers_caught_up: 2,
    nodes: [
      {
        node_id: 'node-a',
        addr: '192.168.178.76:9600',
        role: 'leader',
        matched_index: 12000,
        lag_entries: 0,
        caught_up: true,
      },
    ],
  },
};

describe('DashboardStatsView hierarchy', () => {
  it('renders a posture band and grouped dashboard sections', () => {
    const html = renderToStaticMarkup(<DashboardStatsView stats={stats} />);

    expect(html).toContain('Cluster posture');
    expect(html).toContain('Traffic and policy');
    expect(html).toContain('Control-plane state');
    expect(html).toContain('Replication and system');
  });
});
