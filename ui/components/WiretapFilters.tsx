import React from 'react';
import { WiretapFilterFields } from './wiretap/WiretapFilterFields';
import { WiretapStreamControls } from './wiretap/WiretapStreamControls';
import type { WiretapFilterValues } from './wiretap/types';

interface WiretapFiltersProps {
  filters: WiretapFilterValues;
  onFiltersChange: (filters: WiretapFilterValues) => void;
  disabled?: boolean;
  paused: boolean;
  onPauseToggle: () => void;
  onClear: () => void;
  eventCount: number;
  connected: boolean;
}

export const WiretapFilters: React.FC<WiretapFiltersProps> = ({
  filters,
  onFiltersChange,
  disabled = false,
  paused,
  onPauseToggle,
  onClear,
  eventCount,
  connected,
}) => {
  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-4 space-y-4">
      <WiretapFilterFields filters={filters} onChange={onFiltersChange} disabled={disabled} />
      <WiretapStreamControls
        paused={paused}
        connected={connected}
        eventCount={eventCount}
        onPauseToggle={onPauseToggle}
        onClear={onClear}
        disabled={disabled}
      />
    </div>
  );
};
