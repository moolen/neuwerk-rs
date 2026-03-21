import React from 'react';

import type { ThreatIndicatorType, ThreatSilenceKind } from '../../../types';

interface CreateThreatSilenceModalProps {
  open: boolean;
  title: string;
  description: string;
  kind: ThreatSilenceKind;
  indicatorType: ThreatIndicatorType;
  value: string;
  reason: string;
  saving: boolean;
  lockKind?: boolean;
  lockIndicatorType?: boolean;
  onKindChange?: (kind: ThreatSilenceKind) => void;
  onIndicatorTypeChange?: (indicatorType: ThreatIndicatorType) => void;
  onValueChange: (value: string) => void;
  onReasonChange: (reason: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}

export const CreateThreatSilenceModal: React.FC<CreateThreatSilenceModalProps> = ({
  open,
  title,
  description,
  kind,
  indicatorType,
  value,
  reason,
  saving,
  lockKind = false,
  lockIndicatorType = false,
  onKindChange,
  onIndicatorTypeChange,
  onValueChange,
  onReasonChange,
  onClose,
  onSubmit,
}) => {
  if (!open) {
    return null;
  }

  const exactSelected = kind === 'exact';

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-950/55" onClick={onClose} />
      <section
        className="relative w-full max-w-2xl rounded-[1.8rem] p-6 space-y-5"
        style={{
          background: 'linear-gradient(155deg, var(--bg-glass-strong), rgba(255,255,255,0.14))',
          border: '1px solid var(--border-glass)',
          boxShadow: '0 30px 90px rgba(15,23,42,0.28)',
          backdropFilter: 'blur(16px)',
        }}
      >
        <div className="space-y-2">
          <h3 className="text-xl font-semibold" style={{ color: 'var(--text)' }}>
            {title}
          </h3>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {description}
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2">
            <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
              Silence kind
            </span>
            <select
              value={kind}
              disabled={lockKind}
              onChange={(event) => onKindChange?.(event.target.value as ThreatSilenceKind)}
              className="w-full rounded-[1rem] px-3 py-3"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text)',
              }}
            >
              <option value="exact">Exact</option>
              <option value="hostname_regex">Hostname regex</option>
            </select>
          </label>

          <label className="space-y-2">
            <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
              Indicator type
            </span>
            <select
              value={exactSelected ? indicatorType : 'hostname'}
              disabled={lockIndicatorType || !exactSelected}
              onChange={(event) =>
                onIndicatorTypeChange?.(event.target.value as ThreatIndicatorType)
              }
              className="w-full rounded-[1rem] px-3 py-3"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text)',
              }}
            >
              <option value="hostname">Hostname</option>
              <option value="ip">IP</option>
            </select>
          </label>
        </div>

        <label className="space-y-2">
          <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
            Candidate value
          </span>
          <input
            type="text"
            value={value}
            onChange={(event) => onValueChange(event.target.value)}
            className="w-full rounded-[1rem] px-4 py-3 font-mono text-sm"
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </label>

        <label className="space-y-2">
          <span className="text-sm font-medium" style={{ color: 'var(--text)' }}>
            Reason
          </span>
          <textarea
            value={reason}
            onChange={(event) => onReasonChange(event.target.value)}
            rows={3}
            className="w-full rounded-[1rem] px-4 py-3 text-sm"
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text)',
            }}
          />
        </label>

        <div
          className="rounded-[1.2rem] px-4 py-4 text-sm"
          style={{
            background: 'linear-gradient(135deg, var(--amber-bg), rgba(79,110,247,0.1))',
            border: '1px solid var(--amber-border)',
            color: 'var(--text)',
          }}
        >
          This is cluster-global. future matches will be dropped before finding creation, so the
          silenced indicator will stop producing new threat findings and audit-linked threat
          annotations.
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
          <button
            type="button"
            className="px-4 py-2.5 rounded-full text-sm font-semibold"
            style={{
              background: 'var(--bg-glass-subtle)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
            }}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="button"
            className="px-4 py-2.5 rounded-full text-sm font-semibold"
            style={{
              background: 'linear-gradient(135deg, var(--accent), #3cb7a2)',
              color: '#fff',
              boxShadow: '0 10px 30px rgba(79,110,247,0.2)',
            }}
            disabled={saving}
            onClick={onSubmit}
          >
            {saving ? 'Saving...' : 'Create silence'}
          </button>
        </div>
      </section>
    </div>
  );
};
