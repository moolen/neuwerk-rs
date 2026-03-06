import React from 'react';
import type { AuditFinding } from '../../../types';
import { formatAuditDestination, formatAuditSignals, formatAuditTimestamp } from '../helpers';

interface AuditFindingsTableProps {
  items: AuditFinding[];
}

export const AuditFindingsTable: React.FC<AuditFindingsTableProps> = ({ items }) => (
  <div className="rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
    <table className="w-full">
      <thead>
        <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Type
          </th>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Source Group
          </th>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Destination
          </th>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Signals
          </th>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Count
          </th>
          <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Last Seen
          </th>
        </tr>
      </thead>
      <tbody>
        {items.length === 0 ? (
          <tr>
            <td colSpan={6} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
              No audit findings yet.
            </td>
          </tr>
        ) : (
          items.map((item, idx) => (
            <tr
              key={`${item.finding_type}-${idx}`}
              style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}
            >
              <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                {item.finding_type}
              </td>
              <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-secondary)' }}>
                {item.source_group}
              </td>
              <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                {formatAuditDestination(item)}
              </td>
              <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-muted)' }}>
                {formatAuditSignals(item)}
              </td>
              <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                {item.count}
              </td>
              <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-muted)' }}>
                {formatAuditTimestamp(item.last_seen)}
              </td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  </div>
);
