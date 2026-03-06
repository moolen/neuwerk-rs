import React from 'react';
import type { ServiceAccount, ServiceAccountToken } from '../../../types';
import { ServiceAccountTokensTable } from './ServiceAccountTokensTable';

interface ServiceAccountTokensPanelProps {
  account: ServiceAccount;
  tokenLoading: boolean;
  tokenError: string | null;
  tokens: ServiceAccountToken[];
  onCreateToken: () => void;
  onRevokeToken: (tokenId: string) => void;
}

export const ServiceAccountTokensPanel: React.FC<ServiceAccountTokensPanelProps> = ({
  account,
  tokenLoading,
  tokenError,
  tokens,
  onCreateToken,
  onRevokeToken,
}) => (
  <div
    className="mt-6 rounded-xl p-6"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <div className="flex items-center justify-between">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
          Tokens for {account.name}
        </h2>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          {account.id}
        </p>
      </div>
      <button
        onClick={onCreateToken}
        className="px-3 py-2 text-sm rounded-lg text-white"
        style={{ background: 'var(--accent)' }}
      >
        Create Token
      </button>
    </div>

    {tokenError && (
      <div
        className="mt-4 p-3 rounded-lg"
        style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}
      >
        <p className="text-sm" style={{ color: 'var(--red)' }}>
          {tokenError}
        </p>
      </div>
    )}

    {tokenLoading ? (
      <div className="mt-4 text-sm" style={{ color: 'var(--text-muted)' }}>
        Loading tokens...
      </div>
    ) : tokens.length === 0 ? (
      <div className="mt-4 text-sm" style={{ color: 'var(--text-muted)' }}>
        No tokens yet.
      </div>
    ) : (
      <ServiceAccountTokensTable tokens={tokens} onRevokeToken={onRevokeToken} />
    )}
  </div>
);
