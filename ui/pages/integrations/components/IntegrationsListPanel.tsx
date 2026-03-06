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
    className="rounded-xl overflow-hidden"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <div
      className="px-4 py-3 text-sm font-semibold"
      style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
    >
      Configured Integrations
    </div>
    {loading ? (
      <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
        Loading integrations...
      </div>
    ) : integrations.length === 0 ? (
      <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
        No integrations found.
      </div>
    ) : (
      <div className="divide-y" style={{ borderColor: 'var(--border-glass)' }}>
        {integrations.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelect(item.name)}
            className="w-full text-left p-4"
            style={{
              background: selectedName === item.name ? 'var(--bg-glass-strong)' : 'transparent',
            }}
          >
            <div className="flex items-center justify-between">
              <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                {item.name}
              </div>
              <div
                className="text-[11px] px-2 py-0.5 rounded"
                style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
              >
                {item.kind}
              </div>
            </div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              {item.api_server_url}
            </div>
            <div className="text-xs mt-2" style={{ color: 'var(--text-secondary)' }}>
              token: {item.token_configured ? 'configured' : 'missing'}
            </div>
          </button>
        ))}
      </div>
    )}
  </div>
);
