import React from 'react';
import type { ClusterStats, DhcpStats, DnsStats, TlsStats } from '../../../types';
import { formatEpoch, formatNumber } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';
import { Metric } from './Metric';

interface DashboardControlPlaneSectionProps {
  dns: DnsStats;
  tls: TlsStats;
  dhcp: DhcpStats;
  cluster: ClusterStats;
}

export const DashboardControlPlaneSection: React.FC<DashboardControlPlaneSectionProps> = ({
  dns,
  tls,
  dhcp,
  cluster,
}) => (
  <DashboardSectionCard
    title="Control Plane"
    description="DNS, TLS, DHCP, and leadership signals that shape cluster-wide control behavior."
  >
    <div className="grid grid-cols-2 gap-4 text-sm">
      <Metric label="DNS NXDOMAIN (policy)" value={formatNumber(dns.nxdomain_policy)} />
      <Metric label="DNS NXDOMAIN (upstream)" value={formatNumber(dns.nxdomain_upstream)} />
      <Metric label="TLS Allowed" value={formatNumber(tls.allow)} />
      <Metric label="TLS Denied" value={formatNumber(tls.deny)} />
      <Metric label="DHCP Lease" value={dhcp.lease_active ? 'Active' : 'Inactive'} />
      <Metric label="DHCP Lease Expiry" value={formatEpoch(dhcp.lease_expiry_epoch)} />
      <Metric label="Cluster Leader" value={cluster.is_leader ? 'Yes' : 'No'} />
      <Metric label="Cluster Term" value={formatNumber(cluster.current_term)} />
      <Metric label="Cluster Nodes" value={formatNumber(cluster.node_count)} />
      <Metric
        label="Followers Caught Up"
        value={`${formatNumber(cluster.followers_caught_up)}/${formatNumber(cluster.follower_count)}`}
      />
    </div>
  </DashboardSectionCard>
);
