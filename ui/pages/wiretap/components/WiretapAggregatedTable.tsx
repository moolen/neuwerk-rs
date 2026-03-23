import React from 'react';
import type { AggregatedFlow } from '../types';
import { AGGREGATED_TABLE_COLUMNS } from './aggregatedTableHelpers';
import { WiretapAggregatedTableRow } from './WiretapAggregatedTableRow';
import { formatWiretapTimestamp, wiretapProtoLabel } from '../helpers';
import { formatAggregatedFlowPair, formatAggregatedHostname } from './aggregatedTableHelpers';

interface WiretapAggregatedTableProps {
  flows: AggregatedFlow[];
}

export const WiretapAggregatedTable: React.FC<WiretapAggregatedTableProps> = ({ flows }) => (
  <>
    <div className="md:hidden space-y-3">
      {flows.length === 0 ? (
        <div
          className="rounded-xl p-6 text-center"
          style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}
        >
          No aggregated flows yet.
        </div>
      ) : (
        flows.map((flow) => (
          <div
            key={flow.key}
            className="rounded-xl p-4 space-y-3"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text)' }}>
              {formatAggregatedFlowPair(flow)}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Proto
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {wiretapProtoLabel(flow.proto)}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Flow count
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {flow.flow_count}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Packets in
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {flow.packets_in}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Packets out
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {flow.packets_out}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Hostname
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {formatAggregatedHostname(flow.hostname)}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Last seen
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {formatWiretapTimestamp(flow.last_seen)}
                </div>
              </div>
            </div>
          </div>
        ))
      )}
    </div>

    <div
      className="hidden md:block rounded-xl overflow-x-auto"
      style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
    >
      <table className="w-full min-w-[1040px]">
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
            {AGGREGATED_TABLE_COLUMNS.map((column) => (
              <th
                key={column}
                className="text-left py-3 px-4 text-sm font-medium"
                style={{ color: 'var(--text-secondary)' }}
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {flows.length === 0 ? (
            <tr>
              <td colSpan={7} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
                No aggregated flows yet.
              </td>
            </tr>
          ) : (
            flows.map((flow) => (
              <WiretapAggregatedTableRow key={flow.key} flow={flow} />
            ))
          )}
        </tbody>
      </table>
    </div>
  </>
);
