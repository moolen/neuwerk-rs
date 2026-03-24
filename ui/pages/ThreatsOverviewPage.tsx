import React from 'react';

import { PageLayout } from '../components/layout/PageLayout';
import { ThreatDisableBanner } from './threat-intel/components/ThreatDisableBanner';
import { ThreatFeedStatusPanel } from './threat-intel/components/ThreatFeedStatusPanel';
import { useThreatOverviewPage } from './threat-intel/useThreatOverviewPage';

export const ThreatsOverviewPage: React.FC = () => {
  const {
    feedStatus,
    disabled,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    error,
  } = useThreatOverviewPage();

  return (
    <PageLayout
      title="Threats"
      description="Feed freshness, cluster coverage, and merged pipeline status."
    >
      {error && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--red-bg)',
            border: '1px solid var(--red-border)',
            color: 'var(--red)',
          }}
        >
          {error}
        </div>
      )}

      <ThreatDisableBanner
        disabled={disabled}
        onOpenSettings={() => {
          window.location.assign('/settings');
        }}
      />

      {partial && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--amber-bg)',
            border: '1px solid var(--amber-border)',
            color: 'var(--text)',
          }}
        >
          Partial results: {nodesResponded}/{nodesQueried} nodes responded.
        </div>
      )}

      {nodeErrors.length > 0 && (
        <div
          className="rounded-lg p-4 space-y-2"
          style={{
            background: 'var(--bg-glass-strong)',
            border: '1px solid var(--border-glass)',
            color: 'var(--text)',
          }}
        >
          <h2 className="text-sm font-semibold">Node query errors</h2>
          <ul className="space-y-1 text-sm" style={{ color: 'var(--text-muted)' }}>
            {nodeErrors.map((nodeError) => (
              <li key={`${nodeError.node_id}:${nodeError.error}`}>
                <span style={{ color: 'var(--text)' }}>{nodeError.node_id}</span>: {nodeError.error}
              </li>
            ))}
          </ul>
        </div>
      )}

      <ThreatFeedStatusPanel feedStatus={feedStatus} />
    </PageLayout>
  );
};
