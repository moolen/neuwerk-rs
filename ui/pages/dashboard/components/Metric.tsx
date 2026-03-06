import React from 'react';

interface MetricProps {
  label: string;
  value: string;
}

export const Metric: React.FC<MetricProps> = ({ label, value }) => (
  <div>
    <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
      {label}
    </div>
    <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
      {value}
    </div>
  </div>
);
