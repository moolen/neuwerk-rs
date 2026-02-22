import React from 'react';
import type { ServiceAccount } from '../../types';

interface ServiceAccountTableProps {
  serviceAccounts: ServiceAccount[];
  onDisable: (id: string) => void;
  onSelectTokens: (account: ServiceAccount) => void;
}

const formatTimestamp = (timestamp?: string): string => {
  if (!timestamp) return 'N/A';
  try {
    const date = new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return 'N/A';
  }
};

const statusBadge = (status: ServiceAccount['status']) => {
  const label = status === 'active' ? 'Active' : 'Disabled';
  const style = status === 'active'
    ? { background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)' }
    : { background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' };
  return (
    <span className="inline-flex px-2 py-1 text-xs font-medium rounded" style={style}>
      {label}
    </span>
  );
};

export const ServiceAccountTable: React.FC<ServiceAccountTableProps> = ({
  serviceAccounts,
  onDisable,
  onSelectTokens,
}) => {
  if (serviceAccounts.length === 0) {
    return (
      <div className="rounded-xl border p-12 text-center" style={{ background: 'var(--bg-glass)', borderColor: 'var(--border-glass)' }}>
        <p style={{ color: 'var(--text-muted)' }}>
          No service accounts yet. Click 'Create Service Account' to get started.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
      <table className="w-full">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Name</th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Description</th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Created</th>
            <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Created By</th>
            <th className="text-right py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {serviceAccounts.map((sa) => (
            <tr key={sa.id} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
              <td className="py-3 px-4">
                <div className="font-medium" style={{ color: 'var(--text)' }}>{sa.name}</div>
                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{sa.id.slice(0, 8)}</div>
              </td>
              <td className="py-3 px-4">
                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{sa.description || '-'}</span>
              </td>
              <td className="py-3 px-4">
                {statusBadge(sa.status)}
              </td>
              <td className="py-3 px-4">
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(sa.created_at)}</span>
              </td>
              <td className="py-3 px-4">
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{sa.created_by}</span>
              </td>
              <td className="py-3 px-4">
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => onSelectTokens(sa)}
                    className="px-3 py-1.5 text-xs rounded-lg"
                    style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
                  >
                    Tokens
                  </button>
                  <button
                    onClick={() => onDisable(sa.id)}
                    className="px-3 py-1.5 text-xs rounded-lg"
                    style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
                    disabled={sa.status !== 'active'}
                  >
                    Disable
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
