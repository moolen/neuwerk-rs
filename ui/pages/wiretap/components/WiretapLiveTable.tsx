import React from 'react';
import type { WiretapEvent } from '../../../types';
import { LIVE_TABLE_COLUMNS } from './liveTableHelpers';
import { WiretapLiveTableRow } from './WiretapLiveTableRow';

interface WiretapLiveTableProps {
  events: WiretapEvent[];
}

export const WiretapLiveTable: React.FC<WiretapLiveTableProps> = ({ events }) => (
  <div
    className="rounded-xl overflow-x-auto"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <table className="w-full">
      <thead>
        <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
          {LIVE_TABLE_COLUMNS.map((column) => (
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
        {events.length === 0 ? (
          <tr>
            <td colSpan={6} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
              No wiretap events yet.
            </td>
          </tr>
        ) : (
          events.map((event) => <WiretapLiveTableRow key={event.flow_id} event={event} />)
        )}
      </tbody>
    </table>
  </div>
);
