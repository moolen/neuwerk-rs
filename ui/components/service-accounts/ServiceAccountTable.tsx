import React from 'react';
import type { ServiceAccount } from '../../types';
import { formatServiceAccountTimestamp } from './helpers';
import { ServiceAccountRoleBadge } from './ServiceAccountRoleBadge';
import { ServiceAccountStatusBadge } from './ServiceAccountStatusBadge';
import { ServiceAccountTableEmptyState } from './ServiceAccountTableEmptyState';
import { ServiceAccountTableRow } from './ServiceAccountTableRow';

interface ServiceAccountTableProps {
  serviceAccounts: ServiceAccount[];
  onDisable: (id: string) => void;
  onEdit: (account: ServiceAccount) => void;
  onSelectTokens: (account: ServiceAccount) => void;
}

export const ServiceAccountTable: React.FC<ServiceAccountTableProps> = ({
  serviceAccounts,
  onDisable,
  onEdit,
  onSelectTokens,
}) => {
  if (serviceAccounts.length === 0) {
    return <ServiceAccountTableEmptyState />;
  }

  return (
    <>
      <div className="md:hidden space-y-3">
        {serviceAccounts.map((account) => (
          <div
            key={account.id}
            className="rounded-xl p-4 space-y-4"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-base font-semibold" style={{ color: 'var(--text)' }}>
                  {account.name}
                </div>
                <div className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  {account.id.slice(0, 8)}
                </div>
              </div>
              <ServiceAccountStatusBadge status={account.status} />
            </div>

            <div className="flex flex-wrap gap-2">
              <ServiceAccountRoleBadge role={account.role} />
            </div>

            <div className="grid grid-cols-1 gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Description
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {account.description || '-'}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Created
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {formatServiceAccountTimestamp(account.created_at)}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Created by
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {account.created_by}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => onSelectTokens(account)}
                className="px-3 py-1.5 text-xs rounded-lg"
                style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
              >
                Tokens
              </button>
              <button
                onClick={() => onEdit(account)}
                className="px-3 py-1.5 text-xs rounded-lg"
                style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
              >
                Edit
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
          </div>
        ))}
      </div>

      <div className="hidden md:block rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <table className="w-full min-w-[980px]">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Name</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Description</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Role</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Created</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Created By</th>
              <th className="text-right py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {serviceAccounts.map((sa) => (
              <ServiceAccountTableRow
                key={sa.id}
                account={sa}
                onDisable={onDisable}
                onEdit={onEdit}
                onSelectTokens={onSelectTokens}
              />
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
};
