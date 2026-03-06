import React from 'react';
import type { AggregatedFlow } from '../types';
import { AGGREGATED_TABLE_COLUMNS } from './aggregatedTableHelpers';
import { WiretapAggregatedTableRow } from './WiretapAggregatedTableRow';

interface WiretapAggregatedTableProps {
  flows: AggregatedFlow[];
}

export const WiretapAggregatedTable: React.FC<WiretapAggregatedTableProps> = ({ flows }) => (
  <div
    className="rounded-xl overflow-x-auto"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <table className="w-full">
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
);
