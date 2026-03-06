import React from 'react';
import type { DataplaneStats } from '../../../types';
import { formatBytes } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';
import { Metric } from './Metric';

interface DashboardBytesSectionProps {
  dataplane: DataplaneStats;
}

export const DashboardBytesSection: React.FC<DashboardBytesSectionProps> = ({ dataplane }) => (
  <DashboardSectionCard title="Bytes">
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
      <Metric label="Allowed" value={formatBytes(dataplane.bytes.allow)} />
      <Metric label="Denied" value={formatBytes(dataplane.bytes.deny)} />
      <Metric label="Pending TLS" value={formatBytes(dataplane.bytes.pending_tls)} />
    </div>
  </DashboardSectionCard>
);
