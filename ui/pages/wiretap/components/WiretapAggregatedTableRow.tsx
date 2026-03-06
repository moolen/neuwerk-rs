import React from 'react';

import { formatWiretapTimestamp, wiretapProtoLabel } from '../helpers';
import type { AggregatedFlow } from '../types';
import {
  formatAggregatedFlowPair,
  formatAggregatedHostname,
} from './aggregatedTableHelpers';

interface WiretapAggregatedTableRowProps {
  flow: AggregatedFlow;
}

export const WiretapAggregatedTableRow: React.FC<WiretapAggregatedTableRowProps> = ({ flow }) => (
  <tr style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
    <td className="py-3 px-4">
      <div className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
        {formatAggregatedFlowPair(flow)}
      </div>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {wiretapProtoLabel(flow.proto)}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {flow.flow_count}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {flow.packets_in}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {flow.packets_out}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {formatAggregatedHostname(flow.hostname)}
      </span>
    </td>
    <td className="py-3 px-4">
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        {formatWiretapTimestamp(flow.last_seen)}
      </span>
    </td>
  </tr>
);
