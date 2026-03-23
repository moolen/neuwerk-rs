import React from 'react';
import type { DataplaneStats } from '../../../types';
import { formatNumber } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';
import { Metric } from './Metric';

interface DashboardDataplaneSectionProps {
  dataplane: DataplaneStats;
}

export const DashboardDataplaneSection: React.FC<DashboardDataplaneSectionProps> = ({ dataplane }) => (
  <DashboardSectionCard
    title="Dataplane"
    description="Packet decisions, flow churn, and transport pressure across the forwarding path."
  >
    <div className="grid grid-cols-2 gap-4 text-sm">
      <Metric label="Packets Allowed" value={formatNumber(dataplane.packets.allow)} />
      <Metric label="Packets Denied" value={formatNumber(dataplane.packets.deny)} />
      <Metric label="Packets Pending TLS" value={formatNumber(dataplane.packets.pending_tls)} />
      <Metric label="Flows Opened" value={formatNumber(dataplane.flows_opened)} />
      <Metric label="Flows Closed" value={formatNumber(dataplane.flows_closed)} />
      <Metric
        label="NAT Port Utilization"
        value={`${(dataplane.nat_port_utilization * 100).toFixed(1)}%`}
      />
      <Metric label="IPv4 Fragments Dropped" value={formatNumber(dataplane.ipv4_fragments_dropped)} />
      <Metric label="TTL Exceeded" value={formatNumber(dataplane.ipv4_ttl_exceeded)} />
    </div>
  </DashboardSectionCard>
);
