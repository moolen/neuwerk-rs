import React from 'react';
import { WiretapFilters } from '../components/WiretapFilters';
import { WiretapAggregatedTable } from './wiretap/components/WiretapAggregatedTable';
import { WiretapLiveTable } from './wiretap/components/WiretapLiveTable';
import { WiretapStatusBanners } from './wiretap/components/WiretapStatusBanners';
import { WiretapViewModeToggle } from './wiretap/components/WiretapViewModeToggle';
import { useWiretapPage } from './wiretap/useWiretapPage';

export const WiretapPage: React.FC = () => {
  const {
    events,
    aggregated,
    filters,
    paused,
    bufferedCount,
    connected,
    error,
    viewMode,
    setViewMode,
    setFilters,
    togglePause,
    clear,
  } = useWiretapPage();

  return (
    <div className="space-y-4" style={{ color: 'var(--text)' }}>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>
          Wiretap
        </h1>
        <WiretapViewModeToggle viewMode={viewMode} onChange={setViewMode} />
      </div>

      <WiretapStatusBanners error={error} paused={paused} bufferedCount={bufferedCount} />

      <WiretapFilters
        filters={filters}
        onFiltersChange={setFilters}
        paused={paused}
        onPauseToggle={togglePause}
        onClear={clear}
        eventCount={events.length}
        connected={connected}
      />

      {viewMode === 'live' ? (
        <WiretapLiveTable events={events} />
      ) : (
        <WiretapAggregatedTable flows={aggregated} />
      )}
    </div>
  );
};
