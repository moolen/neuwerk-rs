import React from 'react';

import type { ServiceAccountToken } from '../../../types';
import { canRevokeToken, formatTokenTimestamp } from './tokenTableHelpers';

interface ServiceAccountTokenTableRowProps {
  token: ServiceAccountToken;
  onRevokeToken: (tokenId: string) => void;
}

export const ServiceAccountTokenTableRow: React.FC<ServiceAccountTokenTableRowProps> = ({
  token,
  onRevokeToken,
}) => (
  <tr style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
    <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
      {token.name || '-'}
    </td>
    <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
      {token.status}
    </td>
    <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>
      {formatTokenTimestamp(token.created_at)}
    </td>
    <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>
      {formatTokenTimestamp(token.expires_at)}
    </td>
    <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>
      {formatTokenTimestamp(token.last_used_at)}
    </td>
    <td className="py-2 px-2 text-right">
      <button
        onClick={() => onRevokeToken(token.id)}
        className="px-2 py-1 text-xs rounded-lg"
        style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
        disabled={!canRevokeToken(token.status)}
      >
        Revoke
      </button>
    </td>
  </tr>
);
