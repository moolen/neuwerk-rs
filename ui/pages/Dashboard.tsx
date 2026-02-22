import React, { useEffect, useState } from 'react';
import { Activity, Shield, Globe, Server, AlertTriangle } from 'lucide-react';
import type { StatsResponse } from '../types';
import { getStats } from '../services/api';

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await getStats();
        setStats(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch stats');
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div style={{ color: 'var(--text-muted)' }}>Loading...</div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
        {error || 'Stats unavailable'}
      </div>
    );
  }

  const dp = stats.dataplane;
  const dns = stats.dns;
  const tls = stats.tls;
  const dhcp = stats.dhcp;
  const cluster = stats.cluster;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>Dashboard</h1>
        <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
          Updated every 5s
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Active Flows" value={formatNumber(dp.active_flows)} icon={Activity} colorBg="var(--accent-light)" colorFg="var(--accent)" delay={0} />
        <StatCard title="Active NAT" value={formatNumber(dp.active_nat_entries)} icon={Shield} colorBg="var(--purple-light)" colorFg="var(--purple)" delay={1} />
        <StatCard title="DNS Allowed" value={formatNumber(dns.queries_allow)} icon={Globe} colorBg="var(--green-bg)" colorFg="var(--green)" delay={2} />
        <StatCard title="DNS Denied" value={formatNumber(dns.queries_deny)} icon={AlertTriangle} colorBg="var(--red-bg)" colorFg="var(--red)" delay={3} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="p-6" style={{ background: 'var(--bg-glass-strong)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-glass)' }}>
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>Dataplane</h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <Metric label="Packets Allowed" value={formatNumber(dp.packets.allow)} />
            <Metric label="Packets Denied" value={formatNumber(dp.packets.deny)} />
            <Metric label="Packets Pending TLS" value={formatNumber(dp.packets.pending_tls)} />
            <Metric label="Flows Opened" value={formatNumber(dp.flows_opened)} />
            <Metric label="Flows Closed" value={formatNumber(dp.flows_closed)} />
            <Metric label="NAT Port Utilization" value={`${(dp.nat_port_utilization * 100).toFixed(1)}%`} />
            <Metric label="IPv4 Fragments Dropped" value={formatNumber(dp.ipv4_fragments_dropped)} />
            <Metric label="TTL Exceeded" value={formatNumber(dp.ipv4_ttl_exceeded)} />
          </div>
        </section>

        <section className="p-6" style={{ background: 'var(--bg-glass-strong)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-glass)' }}>
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>Control Plane</h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <Metric label="DNS NXDOMAIN (policy)" value={formatNumber(dns.nxdomain_policy)} />
            <Metric label="DNS NXDOMAIN (upstream)" value={formatNumber(dns.nxdomain_upstream)} />
            <Metric label="TLS Allowed" value={formatNumber(tls.allow)} />
            <Metric label="TLS Denied" value={formatNumber(tls.deny)} />
            <Metric label="DHCP Lease" value={dhcp.lease_active ? 'Active' : 'Inactive'} />
            <Metric label="DHCP Lease Expiry" value={formatEpoch(dhcp.lease_expiry_epoch)} />
            <Metric label="Cluster Leader" value={cluster.is_leader ? 'Yes' : 'No'} />
            <Metric label="Cluster Term" value={formatNumber(cluster.current_term)} />
          </div>
        </section>
      </div>

      <section className="p-6" style={{ background: 'var(--bg-glass-strong)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-glass)' }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>Bytes</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <Metric label="Allowed" value={formatBytes(dp.bytes.allow)} />
          <Metric label="Denied" value={formatBytes(dp.bytes.deny)} />
          <Metric label="Pending TLS" value={formatBytes(dp.bytes.pending_tls)} />
        </div>
      </section>

      <section className="p-6" style={{ background: 'var(--bg-glass-strong)', border: '1px solid var(--border-glass)', borderRadius: 'var(--radius)', boxShadow: 'var(--shadow-glass)' }}>
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--text)' }}>System</h3>
        <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Last applied log index: {formatNumber(cluster.last_applied)} • Last log index: {formatNumber(cluster.last_log_index)}
        </div>
      </section>
    </div>
  );
};

function formatNumber(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

function formatBytes(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2)} GB`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(2)} KB`;
  return `${n} B`;
}

function formatEpoch(epoch: number): string {
  if (!epoch) return 'N/A';
  const date = new Date(epoch * 1000);
  return date.toLocaleString();
}

const Metric = ({ label, value }: { label: string; value: string }) => (
  <div>
    <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</div>
    <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{value}</div>
  </div>
);

const StatCard = ({ title, value, icon: Icon, colorBg, colorFg, delay }: {
  title: string; value: number | string; icon: React.FC<{ className?: string }>; colorBg: string; colorFg: string; delay: number;
}) => (
  <div
    className="p-5 flex items-center justify-between"
    style={{
      background: 'var(--bg-glass-strong)',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
      border: '1px solid var(--border-glass)',
      borderRadius: 'var(--radius)',
      boxShadow: 'var(--shadow-glass)',
      animation: `fadeSlideUp 0.5s ease-out ${delay * 0.05 + 0.05}s backwards`,
    }}
  >
    <div>
      <p className="text-sm font-medium" style={{ color: 'var(--text-muted)' }}>{title}</p>
      <h3 className="text-2xl font-bold mt-1" style={{ color: 'var(--text)', letterSpacing: '-0.5px' }}>{value}</h3>
    </div>
    <div className="p-3" style={{ background: colorBg, color: colorFg, borderRadius: 'var(--radius-sm)' }}>
      <Icon className="w-5 h-5" />
    </div>
  </div>
);
