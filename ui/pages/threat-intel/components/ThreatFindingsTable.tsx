import React from 'react';

import type {
  ThreatEnrichmentStatus,
  ThreatFinding,
  ThreatSeverity,
} from '../../../types';

function formatUnixSeconds(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

function severityColor(severity: ThreatSeverity): string {
  switch (severity) {
    case 'critical':
      return 'var(--red)';
    case 'high':
      return '#ea580c';
    case 'medium':
      return 'var(--amber)';
    case 'low':
      return 'var(--text-secondary)';
  }
}

function enrichmentPalette(status: ThreatEnrichmentStatus): React.CSSProperties {
  switch (status) {
    case 'completed':
      return {
        color: 'var(--green)',
        background: 'var(--green-bg)',
        border: '1px solid var(--green-border)',
      };
    case 'failed':
      return {
        color: 'var(--red)',
        background: 'var(--red-bg)',
        border: '1px solid var(--red-border)',
      };
    case 'running':
    case 'queued':
      return {
        color: 'var(--amber)',
        background: 'var(--amber-bg)',
        border: '1px solid var(--amber-border)',
      };
    case 'not_requested':
      return {
        color: 'var(--text-secondary)',
        background: 'var(--bg-glass-subtle)',
        border: '1px solid var(--border-subtle)',
      };
  }
}

interface ThreatFindingsTableProps {
  items: ThreatFinding[];
  loading: boolean;
  onSilenceExact: (item: ThreatFinding) => void;
  onSilenceHostnameRegex: (item: ThreatFinding) => void;
}

export const ThreatFindingsTable: React.FC<ThreatFindingsTableProps> = ({
  items,
  loading,
  onSilenceExact,
  onSilenceHostnameRegex,
}) => (
  <div
    className="overflow-x-auto rounded-[1.5rem]"
    style={{
      background: 'var(--bg-glass-strong)',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <table className="min-w-full text-sm">
      <thead>
        <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
          {[
            'Indicator',
            'Type',
            'Severity',
            'Feed Hits',
            'First Seen',
            'Last Seen',
            'Count',
            'Observation Layer',
            'Source Group',
            'Sample Nodes',
            'Enrichment',
            'Actions',
          ].map((label) => (
            <th key={label} className="text-left p-3" style={{ color: 'var(--text-muted)' }}>
              {label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {items.length === 0 ? (
          <tr>
            <td className="p-6 text-center" colSpan={12} style={{ color: 'var(--text-muted)' }}>
              {loading
                ? 'Loading findings...'
                : 'No threat findings match the current filters.'}
            </td>
          </tr>
        ) : (
          items.map((item) => (
            <tr
              key={`${item.indicator}:${item.source_group}:${item.observation_layer}:${item.match_source}`}
              style={{ borderBottom: '1px solid var(--border-subtle)' }}
            >
              <td className="p-3 align-top" style={{ color: 'var(--text)' }}>
                <div className="font-semibold">{item.indicator}</div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs">
                  <span
                    className="px-2 py-1 rounded-full"
                    style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}
                  >
                    {item.match_source}
                  </span>
                  <span
                    className="px-2 py-1 rounded-full"
                    style={{
                      background: item.alertable ? 'var(--red-bg)' : 'var(--bg-glass-subtle)',
                      color: item.alertable ? 'var(--red)' : 'var(--text-secondary)',
                    }}
                  >
                    {item.alertable ? 'alertable' : 'observed'}
                  </span>
                </div>
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {item.indicator_type}
              </td>
              <td className="p-3 align-top">
                <span
                  className="px-2.5 py-1 rounded-full font-semibold"
                  style={{
                    color: severityColor(item.severity),
                    background: 'var(--bg-glass-subtle)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {item.severity}
                </span>
              </td>
              <td className="p-3 align-top">
                <div className="flex flex-wrap gap-2">
                  {item.feed_hits.length === 0 ? (
                    <span style={{ color: 'var(--text-muted)' }}>n/a</span>
                  ) : (
                    item.feed_hits.map((hit) => (
                      <span
                        key={`${item.indicator}:${hit.feed}`}
                        className="px-2.5 py-1 rounded-full text-xs"
                        style={{
                          background:
                            'linear-gradient(135deg, rgba(79,110,247,0.12), rgba(16,185,129,0.08))',
                          color: 'var(--text)',
                          border: '1px solid rgba(79,110,247,0.14)',
                        }}
                      >
                        {hit.feed}
                      </span>
                    ))
                  )}
                </div>
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {formatUnixSeconds(item.first_seen)}
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {formatUnixSeconds(item.last_seen)}
              </td>
              <td className="p-3 align-top font-mono" style={{ color: 'var(--text)' }}>
                {item.count}
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {item.observation_layer}
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {item.source_group}
              </td>
              <td className="p-3 align-top" style={{ color: 'var(--text-secondary)' }}>
                {item.sample_node_ids.length > 0 ? item.sample_node_ids.join(', ') : 'n/a'}
              </td>
              <td className="p-3 align-top">
                <span
                  className="px-2.5 py-1 rounded-full text-xs font-medium"
                  style={enrichmentPalette(item.enrichment_status)}
                >
                  {item.enrichment_status}
                </span>
              </td>
              <td className="p-3 align-top">
                <div className="flex flex-col gap-2 min-w-[190px]">
                  <button
                    type="button"
                    className="px-3 py-2 rounded-xl text-left text-xs font-semibold transition-colors"
                    style={{
                      background:
                        'linear-gradient(135deg, rgba(79,110,247,0.14), rgba(16,185,129,0.12))',
                      color: 'var(--text)',
                      border: '1px solid rgba(79,110,247,0.2)',
                    }}
                    onClick={() => onSilenceExact(item)}
                  >
                    Silence exact indicator
                  </button>
                  {item.indicator_type === 'hostname' && (
                    <button
                      type="button"
                      className="px-3 py-2 rounded-xl text-left text-xs font-semibold transition-colors"
                      style={{
                        background: 'var(--bg-glass-subtle)',
                        color: 'var(--text-secondary)',
                        border: '1px solid var(--border-subtle)',
                      }}
                      onClick={() => onSilenceHostnameRegex(item)}
                    >
                      Silence hostname regex
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  </div>
);
