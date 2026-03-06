import React from 'react';

import type { WiretapEvent } from '../../../types';
import { formatWiretapTimestamp, wiretapProtoLabel } from '../helpers';
import { formatLiveFlowLabel, formatLiveHostname } from './liveTableHelpers';

interface WiretapLiveTableRowProps {
  event: WiretapEvent;
}

export const WiretapLiveTableRow: React.FC<WiretapLiveTableRowProps> = ({ event }) => (
  <tr style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
    <td className="py-3 px-4">
      <div className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
        {formatLiveFlowLabel(event)}
      </div>
      <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {event.node_id}
      </div>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {wiretapProtoLabel(event.proto)}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {event.packets_in}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {event.packets_out}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {formatLiveHostname(event.hostname)}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {formatWiretapTimestamp(event.last_seen)}
      </span>
    </td>
  </tr>
);
