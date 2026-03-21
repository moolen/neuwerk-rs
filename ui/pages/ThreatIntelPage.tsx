import React from 'react';

import { ThreatFeedStatusPanel } from './threat-intel/components/ThreatFeedStatusPanel';
import { ThreatFiltersPanel } from './threat-intel/components/ThreatFiltersPanel';
import { ThreatFindingsTable } from './threat-intel/components/ThreatFindingsTable';
import { useThreatIntelPage } from './threat-intel/useThreatIntelPage';

export const ThreatIntelPage: React.FC = () => {
  const {
    items,
    rawItems,
    feedStatus,
    filters,
    availableFeeds,
    availableSourceGroups,
    loading,
    error,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    load,
    updateFilters,
  } = useThreatIntelPage();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text)' }}>
            Threats
          </h1>
          <p className="text-sm mt-2 max-w-2xl" style={{ color: 'var(--text-muted)' }}>
            Cluster-wide intelligence matches, feed freshness, and audit pivots from the
            merged threat pipeline.
          </p>
        </div>

        <div
          className="rounded-[1.3rem] p-4 min-w-[240px]"
          style={{
            background: 'linear-gradient(140deg, rgba(79,110,247,0.13), rgba(16,185,129,0.08))',
            border: '1px solid rgba(79,110,247,0.18)',
            boxShadow: 'var(--shadow-glass)',
          }}
        >
          <div className="text-xs uppercase tracking-[0.26em]" style={{ color: 'var(--text-muted)' }}>
            Visible findings
          </div>
          <div className="mt-2 text-3xl font-bold" style={{ color: 'var(--text)' }}>
            {items.length}
          </div>
          <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
            {rawItems.length} fetched before local indicator and audit filters
          </div>
        </div>
      </div>

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

      {filters.auditKey && (
        <div
          className="rounded-[1.25rem] p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
          style={{
            background: 'linear-gradient(135deg, var(--amber-bg), rgba(79,110,247,0.08))',
            border: '1px solid var(--amber-border)',
          }}
        >
          <div>
            <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
              Audit-linked view
            </div>
            <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              Focusing on threat findings linked to audit key{' '}
              <span className="font-mono">{filters.auditKey}</span>.
            </div>
          </div>
          <button
            type="button"
            className="px-4 py-2 rounded-full text-sm font-medium self-start"
            style={{
              background: 'var(--bg-glass-strong)',
              color: 'var(--text)',
              border: '1px solid var(--border-glass)',
            }}
            onClick={() => updateFilters({ auditKey: null, alertableOnly: true })}
          >
            Return to alertable defaults
          </button>
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
                <span style={{ color: 'var(--text)' }}>{nodeError.node_id}</span>:{' '}
                {nodeError.error}
              </li>
            ))}
          </ul>
        </div>
      )}

      <ThreatFiltersPanel
        filters={filters}
        availableFeeds={availableFeeds}
        availableSourceGroups={availableSourceGroups}
        loading={loading}
        onRefresh={() => void load()}
        onUpdateFilters={updateFilters}
      />

      <ThreatFeedStatusPanel feedStatus={feedStatus} />

      <section className="space-y-3">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Findings
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {items.length} findings match the current view.
          </p>
        </div>
        <ThreatFindingsTable items={items} loading={loading} />
      </section>
    </div>
  );
};
