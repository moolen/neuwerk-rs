import React from 'react';
import type { AuditFinding } from '../../../types';
import { formatAuditDestination, formatAuditSignals, formatAuditTimestamp } from '../helpers';
import type { AuditThreatAnnotation } from '../threatAnnotations';
import { auditFindingKey } from '../threatAnnotations';

interface AuditFindingsTableProps {
  items: AuditFinding[];
  threatAnnotations?: Record<string, AuditThreatAnnotation>;
}

const mobileLabelStyle = {
  color: 'var(--text-muted)',
} as const;

const mobileValueStyle = {
  color: 'var(--text-secondary)',
} as const;

export const AuditFindingsTable: React.FC<AuditFindingsTableProps> = ({
  items,
  threatAnnotations = {},
}) => {
  const threatLinkedCount = items.filter((item) => threatAnnotations[auditFindingKey(item)]).length;

  return (
  <section className="space-y-4">
    <div className="rounded-[1.3rem] p-4 md:p-5" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', boxShadow: 'var(--shadow-glass)' }}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            Review queue
          </div>
          <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            Deny findings are aggregated and deduplicated here for operator review and threat pivots.
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            Finding volume: {items.length}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: threatLinkedCount > 0 ? 'var(--red)' : 'var(--text-secondary)',
              background: threatLinkedCount > 0 ? 'var(--red-bg)' : 'var(--bg-glass-subtle)',
              border: threatLinkedCount > 0 ? '1px solid var(--red-border)' : '1px solid var(--border-glass)',
            }}
          >
            Threat linked: {threatLinkedCount}
          </span>
        </div>
      </div>
    </div>

    <div className="md:hidden space-y-3">
      {items.length === 0 ? (
        <div
          className="rounded-xl p-6 text-center"
          style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}
        >
          No audit findings yet.
        </div>
      ) : (
        items.map((item, idx) => {
          const threatAnnotation = threatAnnotations[auditFindingKey(item)];

          return (
            <div
              key={`${item.finding_type}-${idx}`}
              className="rounded-[1.2rem] p-4 space-y-4"
              style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', boxShadow: 'var(--shadow-glass)' }}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text)' }}>
                    {item.finding_type}
                  </div>
                  <div className="text-xs mt-1" style={mobileLabelStyle}>
                    Finding volume {item.count}
                  </div>
                </div>
                {threatAnnotation ? (
                  <a
                    href={threatAnnotation.href}
                    className="inline-flex items-center gap-2 rounded-full px-2.5 py-1 no-underline"
                    style={{
                      background: 'linear-gradient(135deg, var(--red-bg), rgba(79,110,247,0.1))',
                      color: 'var(--text)',
                      border: '1px solid var(--red-border)',
                    }}
                  >
                    <span className="font-semibold">Threat linked</span>
                    <span>{threatAnnotation.severity}</span>
                  </a>
                ) : null}
              </div>

              <div className="flex flex-wrap gap-2">
                <span
                  className="px-2.5 py-1 rounded-full text-xs font-semibold"
                  style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
                >
                  Review queue
                </span>
                <span
                  className="px-2.5 py-1 rounded-full text-xs font-semibold"
                  style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
                >
                  Nodes {item.node_ids.length}
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <div className="text-[11px] uppercase tracking-[0.18em]" style={mobileLabelStyle}>
                    Source group
                  </div>
                  <div className="mt-1 text-sm" style={mobileValueStyle}>
                    {item.source_group}
                  </div>
                </div>
                <div>
                  <div className="text-[11px] uppercase tracking-[0.18em]" style={mobileLabelStyle}>
                    Destination
                  </div>
                  <div className="mt-1 text-sm font-mono" style={mobileValueStyle}>
                    {formatAuditDestination(item)}
                  </div>
                </div>
                <div>
                  <div className="text-[11px] uppercase tracking-[0.18em]" style={mobileLabelStyle}>
                    Signals
                  </div>
                  <div className="mt-1 text-sm" style={mobileValueStyle}>
                    {formatAuditSignals(item)}
                  </div>
                </div>
                <div>
                  <div className="text-[11px] uppercase tracking-[0.18em]" style={mobileLabelStyle}>
                    Last seen
                  </div>
                  <div className="mt-1 text-sm" style={mobileValueStyle}>
                    {formatAuditTimestamp(item.last_seen)}
                  </div>
                </div>
              </div>
            </div>
          );
        })
      )}
    </div>

    <div className="hidden md:block rounded-[1.2rem] overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', boxShadow: 'var(--shadow-glass)' }}>
      <table className="w-full min-w-[880px]">
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
            items.map((item, idx) => {
              const threatAnnotation = threatAnnotations[auditFindingKey(item)];

              return (
                <tr
                  key={`${item.finding_type}-${idx}`}
                  style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}
                >
                  <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                    <div>{item.finding_type}</div>
                    <div className="mt-2 text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                      Review queue
                    </div>
                    {threatAnnotation && (
                      <a
                        href={threatAnnotation.href}
                        className="mt-2 inline-flex items-center gap-2 rounded-full px-2.5 py-1 no-underline"
                        style={{
                          background: 'linear-gradient(135deg, var(--red-bg), rgba(79,110,247,0.1))',
                          color: 'var(--text)',
                          border: '1px solid var(--red-border)',
                        }}
                      >
                        <span className="font-semibold">Threat linked</span>
                        <span>{threatAnnotation.severity}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{threatAnnotation.matchCount}x</span>
                      </a>
                    )}
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
              );
            })
          )}
        </tbody>
      </table>
    </div>
  </section>
  );
};
