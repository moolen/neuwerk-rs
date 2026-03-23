import React from 'react';
import { Activity, AlertTriangle, Globe, Shield } from 'lucide-react';
import type { DataplaneStats, DnsStats } from '../../../types';
import { formatNumber } from '../helpers';
import { StatCard } from './StatCard';

interface DashboardOverviewCardsProps {
  dataplane: DataplaneStats;
  dns: DnsStats;
}

export const DashboardOverviewCards: React.FC<DashboardOverviewCardsProps> = ({ dataplane, dns }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <StatCard
      title="Active Flows"
      value={formatNumber(dataplane.active_flows)}
      detail="Current dataplane concurrency across allowed and pending sessions."
      icon={Activity}
      colorBg="var(--accent-light)"
      colorFg="var(--accent)"
      delay={0}
    />
    <StatCard
      title="Active NAT"
      value={formatNumber(dataplane.active_nat_entries)}
      detail={`${(dataplane.nat_port_utilization * 100).toFixed(1)}% port utilization`}
      icon={Shield}
      colorBg="var(--purple-light)"
      colorFg="var(--purple)"
      delay={1}
    />
    <StatCard
      title="DNS Allowed"
      value={formatNumber(dns.queries_allow)}
      detail="Queries resolved or permitted by the current control-plane path."
      icon={Globe}
      colorBg="var(--green-bg)"
      colorFg="var(--green)"
      delay={2}
    />
    <StatCard
      title="DNS Denied"
      value={formatNumber(dns.queries_deny)}
      detail="Queries blocked by policy and surfaced for operator review."
      icon={AlertTriangle}
      colorBg="var(--red-bg)"
      colorFg="var(--red)"
      delay={3}
    />
  </div>
);
