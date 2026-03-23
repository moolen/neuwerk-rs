import React from 'react';
import type { IntegrationView } from '../../../types';

interface IntegrationsListPanelProps {
  loading: boolean;
  integrations: IntegrationView[];
  selectedName: string | null;
  onSelect: (name: string) => void;
}

export const IntegrationsListPanel: React.FC<IntegrationsListPanelProps> = ({
  loading,
  integrations,
  selectedName,
  onSelect,
}) => (
  <div
    className="rounded-[1.5rem] p-4 space-y-4"
    style={{
      background: 'var(--bg-glass)',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex items-start justify-between gap-3">
      <div>
        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
          Configured Integrations
        </div>
        <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
          Choose the inventory source backing dynamic selectors in policy rules.
        </div>
      </div>
      <div
        className="px-2.5 py-1 rounded-full text-xs font-semibold"
        style={{
          background: 'var(--bg-glass-strong)',
          border: '1px solid var(--border-glass)',
          color: 'var(--text-secondary)',
        }}
      >
        {integrations.length}
      </div>
    </div>

    {loading ? (
      <div className="rounded-[1rem] p-4 text-sm" style={{ color: 'var(--text-muted)', background: 'var(--bg-glass-subtle)' }}>
        Loading integrations...
      </div>
    ) : integrations.length === 0 ? (
      <div className="rounded-[1rem] p-4 text-sm" style={{ color: 'var(--text-muted)', background: 'var(--bg-glass-subtle)' }}>
        No integrations yet. Create the first Kubernetes inventory source.
      </div>
    ) : (
      <div className="space-y-3">
        {integrations.map((item) => {
          const selected = selectedName === item.name;

          return (
            <button
              key={item.id}
              onClick={() => onSelect(item.name)}
              className="w-full text-left rounded-[1.15rem] p-4 transition-colors"
              style={{
                background: selected
                  ? 'linear-gradient(145deg, rgba(79,110,247,0.14), rgba(79,110,247,0.05))'
                  : 'var(--bg-glass-subtle)',
                border: selected ? '1px solid rgba(79,110,247,0.22)' : '1px solid var(--border-glass)',
                boxShadow: selected ? 'var(--shadow-glass)' : 'none',
              }}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                    {item.name}
                  </div>
                  <div className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {item.kind}
                  </div>
                </div>
                <div
                  className="px-2.5 py-1 rounded-full text-[11px] font-semibold"
                  style={{
                    background: selected ? 'rgba(79,110,247,0.16)' : 'var(--bg-input)',
                    color: selected ? 'var(--accent)' : 'var(--text-secondary)',
                  }}
                >
                  {selected ? 'Selected' : 'Available'}
                </div>
              </div>

              <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                    API server
                  </dt>
                  <dd className="mt-1 text-xs break-all" style={{ color: 'var(--text-secondary)' }}>
                    {item.api_server_url}
                  </dd>
                </div>
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                    Auth
                  </dt>
                  <dd className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {item.token_configured ? 'Service account token configured' : 'Service account token missing'}
                  </dd>
                </div>
              </dl>
            </button>
          );
        })}
      </div>
    )}
  </div>
);
