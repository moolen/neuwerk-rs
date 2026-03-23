import React from 'react';
import { PageLayout } from '../components/layout/PageLayout';
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
    performanceModeEnabled,
    performanceModeLoading,
    performanceModeError,
    viewMode,
    setViewMode,
    setFilters,
    togglePause,
    clear,
  } = useWiretapPage();

  return (
    <PageLayout
      title="Wiretap"
      description="Inspect live and aggregated traffic samples, with controls gated by performance mode."
      actions={
        <WiretapViewModeToggle
          viewMode={viewMode}
          onChange={setViewMode}
          disabled={!performanceModeEnabled}
        />
      }
    >

      {performanceModeError && (
        <div
          className="rounded-lg p-4"
          style={{ background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))', border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))' }}
        >
          <p className="text-sm" style={{ color: 'var(--text)' }}>
            {performanceModeError}
          </p>
        </div>
      )}

      {!performanceModeLoading && !performanceModeEnabled && (
        <div
          className="rounded-lg p-4"
          style={{ background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))', border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))' }}
        >
          <p className="text-sm" style={{ color: 'var(--text)' }}>
            Performance mode is disabled. Wiretap is unavailable until it is re-enabled in Settings.
          </p>
        </div>
      )}

      <WiretapStatusBanners error={error} paused={paused} bufferedCount={bufferedCount} />

      <WiretapFilters
        filters={filters}
        onFiltersChange={setFilters}
        disabled={!performanceModeEnabled}
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
    </PageLayout>
  );
};
