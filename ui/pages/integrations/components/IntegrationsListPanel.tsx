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
    <div>
      <div>
        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
          Configured Integrations
        </div>
        <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
          Choose the inventory source backing dynamic selectors in policy rules.
        </div>
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
              <div>
                <div>
                  <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                    {item.name}
                  </div>
                  <div className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
                    {item.kind}
                  </div>
                </div>
              </div>

              <dl className="mt-4">
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                    API server
                  </dt>
                  <dd className="mt-1 text-xs break-all" style={{ color: 'var(--text-secondary)' }}>
                    {item.api_server_url}
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
