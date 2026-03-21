import React, { useMemo } from 'react';
import { AuditFindingsTable } from './audit/components/AuditFindingsTable';
import { AuditFiltersPanel } from './audit/components/AuditFiltersPanel';
import { AuditNodeErrorsPanel } from './audit/components/AuditNodeErrorsPanel';
import { useAuditPage } from './audit/useAuditPage';

export const AuditPage: React.FC = () => {
  const {
    items,
    loading,
    error,
    partial,
    nodes,
    nodeErrors,
    typeFilter,
    setTypeFilter,
    sourceGroup,
    setSourceGroup,
    policyId,
    setPolicyId,
    load,
    threatAnnotations,
    performanceModeEnabled,
    performanceModeLoading,
    performanceModeError,
  } = useAuditPage();

  const filtered = useMemo(() => items, [items]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>
          Audit
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Persisted policy deny findings (cluster-aggregated, deduplicated).
        </p>
      </div>

      <AuditFiltersPanel
        typeFilter={typeFilter}
        sourceGroup={sourceGroup}
        policyId={policyId}
        loading={loading}
        disabled={!performanceModeEnabled}
        onTypeFilterChange={setTypeFilter}
        onSourceGroupChange={setSourceGroup}
        onPolicyIdChange={setPolicyId}
        onRefresh={() => void load()}
      />

      {performanceModeError && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))',
            border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))',
            color: 'var(--text)',
          }}
        >
          {performanceModeError}
        </div>
      )}

      {!performanceModeLoading && !performanceModeEnabled && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))',
            border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))',
            color: 'var(--text)',
          }}
        >
          Performance mode is disabled. Audit is unavailable until it is re-enabled in Settings.
        </div>
      )}

      {error && (
        <div
          className="rounded-lg p-4"
          style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}
        >
          {error}
        </div>
      )}

      {partial && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))',
            border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))',
            color: 'var(--text)',
          }}
        >
          Partial results: {nodes.responded}/{nodes.queried} nodes responded.
        </div>
      )}

      <AuditNodeErrorsPanel nodeErrors={nodeErrors} />

      <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {filtered.length} findings
      </div>

      <AuditFindingsTable items={filtered} threatAnnotations={threatAnnotations} />
    </div>
  );
};
