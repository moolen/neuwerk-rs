import React from 'react';
import type { ServiceAccount } from '../../types';
import { formatServiceAccountTimestamp } from './helpers';
import { ServiceAccountStatusBadge } from './ServiceAccountStatusBadge';

interface ServiceAccountTableRowProps {
  account: ServiceAccount;
  onDisable: (id: string) => void;
  onSelectTokens: (account: ServiceAccount) => void;
}

export const ServiceAccountTableRow: React.FC<ServiceAccountTableRowProps> = ({
  account,
  onDisable,
  onSelectTokens,
}) => (
  <tr key={account.id} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
    <td className="py-3 px-4">
      <div className="font-medium" style={{ color: 'var(--text)' }}>
        {account.name}
      </div>
      <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {account.id.slice(0, 8)}
      </div>
    </td>
    <td className="py-3 px-4">
      <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        {account.description || '-'}
      </span>
    </td>
    <td className="py-3 px-4">
      <ServiceAccountStatusBadge status={account.status} />
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {formatServiceAccountTimestamp(account.created_at)}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {account.created_by}
      </span>
    </td>
    <td className="py-3 px-4">
      <div className="flex justify-end gap-2">
        <button
          onClick={() => onSelectTokens(account)}
          className="px-3 py-1.5 text-xs rounded-lg"
          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
        >
          Tokens
        </button>
        <button
          onClick={() => onDisable(account.id)}
          className="px-3 py-1.5 text-xs rounded-lg"
          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
          disabled={account.status !== 'active'}
        >
          Disable
        </button>
      </div>
    </td>
  </tr>
);
