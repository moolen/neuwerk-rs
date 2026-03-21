import React from 'react';

import type { ThreatSilenceEntry } from '../../../types';

interface ThreatSilencesPanelProps {
  items: ThreatSilenceEntry[];
  loading: boolean;
  deletingId: string | null;
  onDelete: (id: string) => void;
  onCreateManual: () => void;
}

function formatCreatedAt(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

function silenceKindLabel(item: ThreatSilenceEntry): string {
  if (item.kind === 'hostname_regex') {
    return 'Hostname regex';
  }
  return item.indicator_type === 'ip' ? 'Exact IP' : 'Exact hostname';
}

export const ThreatSilencesPanel: React.FC<ThreatSilencesPanelProps> = ({
  items,
  loading,
  deletingId,
  onDelete,
  onCreateManual,
}) => (
  <section
    className="rounded-[1.5rem] p-5 space-y-4"
    style={{
      background: 'linear-gradient(135deg, var(--bg-glass-strong), var(--bg-glass-subtle))',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
          Silences
        </h2>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Global suppressions applied before new findings are created.
        </p>
      </div>
      <button
        type="button"
        className="px-4 py-2.5 rounded-full text-sm font-semibold self-start"
        style={{
          background: 'linear-gradient(135deg, var(--accent), #3cb7a2)',
          color: '#fff',
          boxShadow: '0 10px 30px rgba(79,110,247,0.2)',
        }}
        onClick={onCreateManual}
      >
        Add silence
      </button>
    </div>

    <div className="space-y-3">
      {items.length === 0 ? (
        <div
          className="rounded-[1.2rem] px-4 py-5 text-sm"
          style={{
            background: 'var(--bg-glass-subtle)',
            border: '1px dashed var(--border-subtle)',
            color: 'var(--text-muted)',
          }}
        >
          {loading ? 'Loading silences...' : 'No silences configured yet.'}
        </div>
      ) : (
        items.map((item) => (
          <article
            key={item.id}
            className="rounded-[1.2rem] p-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"
            style={{
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className="px-2.5 py-1 rounded-full text-xs font-semibold"
                  style={{
                    color: 'var(--accent)',
                    background: 'var(--accent-soft)',
                  }}
                >
                  {silenceKindLabel(item)}
                </span>
                <span className="font-mono text-sm" style={{ color: 'var(--text)' }}>
                  {item.value}
                </span>
              </div>
              {item.reason && (
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {item.reason}
                </p>
              )}
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Created {formatCreatedAt(item.created_at)}
              </div>
            </div>

            <button
              type="button"
              className="px-3 py-2 rounded-xl text-sm font-semibold self-start"
              style={{
                background: deletingId === item.id ? 'var(--bg-glass-subtle)' : 'var(--red-bg)',
                color: deletingId === item.id ? 'var(--text-secondary)' : 'var(--red)',
                border: '1px solid var(--red-border)',
                opacity: deletingId === item.id ? 0.75 : 1,
              }}
              disabled={deletingId === item.id}
              onClick={() => onDelete(item.id)}
            >
              {deletingId === item.id ? 'Deleting...' : 'Delete'}
            </button>
          </article>
        ))
      )}
    </div>
  </section>
);
