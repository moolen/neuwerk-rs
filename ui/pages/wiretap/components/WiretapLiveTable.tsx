import React from 'react';
import type { WiretapEvent } from '../../../types';
import { formatWiretapTimestamp, wiretapProtoLabel } from '../helpers';
import { LIVE_TABLE_COLUMNS } from './liveTableHelpers';
import { formatLiveFlowLabel, formatLiveHostname } from './liveTableHelpers';
import { WiretapLiveTableRow } from './WiretapLiveTableRow';

interface WiretapLiveTableProps {
  events: WiretapEvent[];
}

export const WiretapLiveTable: React.FC<WiretapLiveTableProps> = ({ events }) => (
  <>
    <div className="md:hidden space-y-3">
      {events.length === 0 ? (
        <div
          className="rounded-xl p-6 text-center"
          style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}
        >
          No wiretap events yet.
        </div>
      ) : (
        events.map((event) => (
          <div
            key={event.flow_id}
            className="rounded-xl p-4 space-y-3"
            style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
          >
            <div>
              <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text)' }}>
                {formatLiveFlowLabel(event)}
              </div>
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {event.node_id}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Proto
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {wiretapProtoLabel(event.proto)}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Hostname
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {formatLiveHostname(event.hostname)}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Packets in
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {event.packets_in}
                </div>
              </div>
              <div>
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Packets out
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {event.packets_out}
                </div>
              </div>
              <div className="col-span-2">
                <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                  Last seen
                </div>
                <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {formatWiretapTimestamp(event.last_seen)}
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
      <table className="w-full min-w-[960px]">
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
  </>
);
