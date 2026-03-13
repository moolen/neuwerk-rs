import React from 'react';

import type { ServiceAccountToken } from '../../../types';
import { ServiceAccountTokenTableRow } from './ServiceAccountTokenTableRow';

interface ServiceAccountTokensTableProps {
  tokens: ServiceAccountToken[];
  onRevokeToken: (tokenId: string) => void;
}

export const ServiceAccountTokensTable: React.FC<ServiceAccountTokensTableProps> = ({
  tokens,
  onRevokeToken,
}) => (
  <div className="mt-4 overflow-x-auto">
    <table className="w-full">
      <thead>
        <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Name
          </th>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Role
          </th>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Status
          </th>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Created
          </th>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Expires
          </th>
          <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Last Used
          </th>
          <th className="text-right py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Actions
          </th>
        </tr>
      </thead>
      <tbody>
        {tokens.map((token) => (
          <ServiceAccountTokenTableRow
            key={token.id}
            token={token}
            onRevokeToken={onRevokeToken}
          />
        ))}
      </tbody>
    </table>
  </div>
);
