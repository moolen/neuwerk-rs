import React from 'react';

import { PageLayout } from '../components/layout/PageLayout';
import type { ThreatFinding, ThreatIndicatorType, ThreatSilenceKind } from '../types';
import { CreateThreatSilenceModal } from './threat-intel/components/CreateThreatSilenceModal';
import { ThreatDisableBanner } from './threat-intel/components/ThreatDisableBanner';
import { ThreatFiltersPanel } from './threat-intel/components/ThreatFiltersPanel';
import { ThreatFindingsTable } from './threat-intel/components/ThreatFindingsTable';
import { useThreatFindingsPage } from './threat-intel/useThreatFindingsPage';

interface SilenceDraftState {
  title: string;
  description: string;
  kind: ThreatSilenceKind;
  indicatorType: ThreatIndicatorType;
  value: string;
  reason: string;
  lockKind: boolean;
  lockIndicatorType: boolean;
}

function escapeRegexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hostnameRegexSuggestion(hostname: string): string {
  return `^${escapeRegexLiteral(hostname.toLowerCase())}$`;
}

export const ThreatFindingsPage: React.FC = () => {
  const {
    items,
    rawItems,
    filters,
    availableFeeds,
    availableSourceGroups,
    loading,
    error,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    disabled,
    silenceSaving,
    load,
    updateFilters,
    createSilence,
  } = useThreatFindingsPage();
  const [silenceDraft, setSilenceDraft] = React.useState<SilenceDraftState | null>(null);

  const openExactSilence = (item: ThreatFinding) => {
    setSilenceDraft({
      title: 'Silence exact indicator',
      description: 'Create a global silence for future matches of this exact indicator.',
      kind: 'exact',
      indicatorType: item.indicator_type,
      value: item.indicator,
      reason: '',
      lockKind: true,
      lockIndicatorType: true,
    });
  };

  const openHostnameRegexSilence = (item: ThreatFinding) => {
    setSilenceDraft({
      title: 'Silence hostname regex',
      description:
        'Create a hostname-only regex silence. Adjust the pattern if you want to broaden the suppression scope.',
      kind: 'hostname_regex',
      indicatorType: 'hostname',
      value: hostnameRegexSuggestion(item.indicator),
      reason: '',
      lockKind: true,
      lockIndicatorType: true,
    });
  };

  const submitSilence = async () => {
    if (!silenceDraft) {
      return;
    }
    await createSilence({
      kind: silenceDraft.kind,
      indicator_type: silenceDraft.kind === 'exact' ? silenceDraft.indicatorType : undefined,
      value: silenceDraft.value,
      reason: silenceDraft.reason.trim() || undefined,
    });
    setSilenceDraft(null);
  };

  return (
    <PageLayout
      title="Findings"
      description="Investigate threat matches from the merged threat pipeline."
      actions={
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
      }
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
                <span style={{ color: 'var(--text)' }}>{nodeError.node_id}</span>: {nodeError.error}
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

      <section className="space-y-3">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Findings
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {disabled
              ? 'Threat findings are hidden while threat analysis is disabled.'
              : `${items.length} findings match the current view.`}
          </p>
        </div>
        {disabled ? (
          <div
            className="rounded-[1.4rem] p-6 text-sm"
            style={{
              background: 'var(--bg-glass-subtle)',
              border: '1px dashed var(--border-subtle)',
              color: 'var(--text-muted)',
            }}
          >
            Re-enable threat analysis from Settings to resume URL and IP processing and to reveal
            stored findings again.
          </div>
        ) : (
          <ThreatFindingsTable
            items={items}
            loading={loading}
            onSilenceExact={openExactSilence}
            onSilenceHostnameRegex={openHostnameRegexSilence}
          />
        )}
      </section>

      <CreateThreatSilenceModal
        open={silenceDraft !== null}
        title={silenceDraft?.title ?? ''}
        description={silenceDraft?.description ?? ''}
        kind={silenceDraft?.kind ?? 'exact'}
        indicatorType={silenceDraft?.indicatorType ?? 'hostname'}
        value={silenceDraft?.value ?? ''}
        reason={silenceDraft?.reason ?? ''}
        saving={silenceSaving}
        lockKind={silenceDraft?.lockKind}
        lockIndicatorType={silenceDraft?.lockIndicatorType}
        onKindChange={(kind) =>
          setSilenceDraft((current) =>
            current
              ? {
                  ...current,
                  kind,
                  indicatorType: kind === 'hostname_regex' ? 'hostname' : current.indicatorType,
                }
              : current,
          )
        }
        onIndicatorTypeChange={(indicatorType) =>
          setSilenceDraft((current) => (current ? { ...current, indicatorType } : current))
        }
        onValueChange={(value) =>
          setSilenceDraft((current) => (current ? { ...current, value } : current))
        }
        onReasonChange={(reason) =>
          setSilenceDraft((current) => (current ? { ...current, reason } : current))
        }
        onClose={() => setSilenceDraft(null)}
        onSubmit={() => void submitSilence()}
      />
    </PageLayout>
  );
};
