import React from 'react';
import type { ServiceAccount } from '../../types';
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
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
      <table className="w-full">
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
  );
};
