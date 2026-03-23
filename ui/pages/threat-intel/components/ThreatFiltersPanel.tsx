import React from 'react';

import type { ThreatFilters, ThreatTimeRange } from '../helpers';

interface ThreatFiltersPanelProps {
  filters: ThreatFilters;
  availableFeeds: string[];
  availableSourceGroups: string[];
  loading: boolean;
  onRefresh: () => void;
  onUpdateFilters: (patch: Partial<ThreatFilters>) => void;
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'] as const;
const LAYER_OPTIONS = ['dns', 'tls', 'l4'] as const;
const MATCH_SOURCE_OPTIONS = ['stream', 'backfill'] as const;
const INDICATOR_TYPE_OPTIONS = ['hostname', 'ip'] as const;
const TIME_RANGE_OPTIONS: Array<{ value: ThreatTimeRange; label: string }> = [
  { value: '1h', label: '1h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: 'all', label: 'All' },
];

function panelStyle(): React.CSSProperties {
  return {
    background: 'linear-gradient(135deg, var(--bg-glass-strong), var(--bg-glass-subtle))',
    border: '1px solid var(--border-glass)',
    boxShadow: 'var(--shadow-glass)',
  };
}

function inputStyle(): React.CSSProperties {
  return {
    width: '100%',
    padding: '0.75rem 0.9rem',
    borderRadius: '0.9rem',
    border: '1px solid var(--border-subtle)',
    background: 'var(--bg-input)',
    color: 'var(--text)',
  };
}

function laneStyle(): React.CSSProperties {
  return {
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid var(--border-glass)',
  };
}

function toggleArrayValue<T extends string>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function FilterChip({
  active,
  children,
  onClick,
}: {
  active: boolean;
  children: React.ReactNode;
  onClick: () => void;
}): React.ReactElement {
  return (
    <button
      type="button"
      className="px-3 py-2 rounded-full text-sm font-medium transition-colors"
      style={{
        border: active ? '1px solid rgba(79, 110, 247, 0.28)' : '1px solid var(--border-subtle)',
        background: active
          ? 'linear-gradient(135deg, var(--accent-soft), rgba(16,185,129,0.08))'
          : 'var(--bg-glass-subtle)',
        color: active ? 'var(--text)' : 'var(--text-secondary)',
      }}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function FilterSection({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <div className="space-y-3">
      <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div className="flex flex-wrap gap-2">{children}</div>
    </div>
  );
}

export const ThreatFiltersPanel: React.FC<ThreatFiltersPanelProps> = ({
  filters,
  availableFeeds,
  availableSourceGroups,
  loading,
  onRefresh,
  onUpdateFilters,
}) => (
  <section className="rounded-[1.5rem] p-5 space-y-5" style={panelStyle()}>
    <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
          Investigate
        </h2>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Narrow the active findings by indicator, feed, scope, and time horizon.
        </p>
      </div>
      <button
        type="button"
        className="px-4 py-2.5 rounded-full text-sm font-semibold self-start"
        style={{
          background: 'linear-gradient(135deg, var(--accent), #3cb7a2)',
          color: '#fff',
          boxShadow: '0 10px 30px rgba(79,110,247,0.25)',
        }}
        onClick={onRefresh}
        disabled={loading}
      >
        {loading ? 'Refreshing...' : 'Refresh'}
      </button>
    </div>

    <div className="grid gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(19rem,0.95fr)] 2xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.9fr)]">
      <div className="space-y-5">
        <section className="rounded-[1.2rem] p-4 space-y-4" style={laneStyle()}>
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
              Refine by feed and severity
            </h3>
            <p className="mt-1 text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
              Start with the indicator and feed mix, then tighten the visible findings by severity.
            </p>
          </div>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <label className="space-y-2">
              <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
                Hostname or IP
              </span>
              <input
                type="search"
                placeholder="bad.example.com or 203.0.113.10"
                value={filters.indicatorQuery}
                onChange={(event) => onUpdateFilters({ indicatorQuery: event.target.value })}
                style={inputStyle()}
              />
            </label>

            <label className="space-y-2">
              <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
                Source group
              </span>
              <input
                type="text"
                list="threat-source-groups"
                placeholder="All source groups"
                value={filters.sourceGroup}
                onChange={(event) => onUpdateFilters({ sourceGroup: event.target.value })}
                style={inputStyle()}
              />
              <datalist id="threat-source-groups">
                {availableSourceGroups.map((item) => (
                  <option key={item} value={item} />
                ))}
              </datalist>
            </label>
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <FilterSection label="Feed">
              {availableFeeds.map((feed) => (
                <FilterChip
                  key={feed}
                  active={filters.selectedFeeds.includes(feed)}
                  onClick={() =>
                    onUpdateFilters({
                      selectedFeeds: toggleArrayValue(filters.selectedFeeds, feed),
                    })
                  }
                >
                  {feed}
                </FilterChip>
              ))}
            </FilterSection>

            <FilterSection label="Severity">
              {SEVERITY_OPTIONS.map((severity) => (
                <FilterChip
                  key={severity}
                  active={filters.selectedSeverities.includes(severity)}
                  onClick={() =>
                    onUpdateFilters({
                      selectedSeverities: toggleArrayValue(filters.selectedSeverities, severity),
                    })
                  }
                >
                  {severity}
                </FilterChip>
              ))}
            </FilterSection>

            <FilterSection label="Indicator type">
              {INDICATOR_TYPE_OPTIONS.map((type) => (
                <FilterChip
                  key={type}
                  active={filters.selectedIndicatorTypes.includes(type)}
                  onClick={() =>
                    onUpdateFilters({
                      selectedIndicatorTypes: toggleArrayValue(filters.selectedIndicatorTypes, type),
                    })
                  }
                >
                  {type}
                </FilterChip>
              ))}
            </FilterSection>
          </div>
        </section>
      </div>

      <div className="space-y-5">
        <section className="rounded-[1.2rem] p-4 space-y-4" style={laneStyle()}>
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
              Scope and timing
            </h3>
            <p className="mt-1 text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
              Narrow the operational context by network layer, ingestion timing, and alert posture.
            </p>
          </div>

          <div className="space-y-5">
            <FilterSection label="Observation layer">
              {LAYER_OPTIONS.map((layer) => (
                <FilterChip
                  key={layer}
                  active={filters.selectedLayers.includes(layer)}
                  onClick={() =>
                    onUpdateFilters({
                      selectedLayers: toggleArrayValue(filters.selectedLayers, layer),
                    })
                  }
                >
                  {layer}
                </FilterChip>
              ))}
            </FilterSection>

            <FilterSection label="Time range">
              {TIME_RANGE_OPTIONS.map((option) => (
                <FilterChip
                  key={option.value}
                  active={filters.timeRange === option.value}
                  onClick={() => onUpdateFilters({ timeRange: option.value })}
                >
                  {option.label}
                </FilterChip>
              ))}
            </FilterSection>

            <FilterSection label="Match source">
              {MATCH_SOURCE_OPTIONS.map((source) => (
                <FilterChip
                  key={source}
                  active={filters.selectedMatchSources.includes(source)}
                  onClick={() =>
                    onUpdateFilters({
                      selectedMatchSources: toggleArrayValue(filters.selectedMatchSources, source),
                    })
                  }
                >
                  {source}
                </FilterChip>
              ))}
            </FilterSection>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4" style={{ borderColor: 'var(--border-glass)' }}>
            <label
              className="inline-flex items-center gap-3 rounded-full px-4 py-2"
              style={{ background: 'var(--bg-glass-subtle)' }}
            >
              <input
                type="checkbox"
                checked={filters.alertableOnly}
                onChange={(event) => onUpdateFilters({ alertableOnly: event.target.checked })}
              />
              <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
                Alertable only
              </span>
            </label>

            {filters.auditKey && (
              <button
                type="button"
                className="text-sm font-medium underline underline-offset-4"
                style={{ color: 'var(--accent)' }}
                onClick={() => onUpdateFilters({ auditKey: null, alertableOnly: true })}
              >
                Clear audit focus
              </button>
            )}
          </div>
        </section>
      </div>
    </div>
  </section>
);
