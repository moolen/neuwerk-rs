import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { WiretapEvent } from '../../types';
import { getPerformanceModeStatus } from '../../services/api';
import { aggregateWiretapFlows, filterWiretapEvents, MAX_WIRETAP_EVENTS } from './helpers';
import {
  defaultWiretapFilters,
  flushBufferedEvents,
  type WiretapFiltersState,
  upsertWiretapEvent,
} from './state';
import type { ViewMode } from './types';
import { useWiretapConnection } from './useWiretapConnection';

export function useWiretapPage() {
  const [events, setEvents] = useState<WiretapEvent[]>([]);
  const [bufferedEvents, setBufferedEvents] = useState<WiretapEvent[]>([]);
  const [filters, setFilters] = useState<WiretapFiltersState>(defaultWiretapFilters);
  const [paused, setPaused] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('live');
  const [performanceModeEnabled, setPerformanceModeEnabled] = useState(true);
  const [performanceModeLoading, setPerformanceModeLoading] = useState(true);
  const [performanceModeError, setPerformanceModeError] = useState<string | null>(null);
  const pausedRef = useRef(false);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  const handleWiretapEvent = useCallback((event: WiretapEvent) => {
    if (pausedRef.current) {
      setBufferedEvents((prev) => [event, ...prev]);
      return;
    }
    setEvents((prev) => upsertWiretapEvent(prev, event, MAX_WIRETAP_EVENTS));
  }, []);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        setPerformanceModeLoading(true);
        setPerformanceModeError(null);
        const status = await getPerformanceModeStatus();
        if (cancelled) {
          return;
        }
        setPerformanceModeEnabled(status.enabled);
      } catch (err) {
        if (cancelled) {
          return;
        }
        setPerformanceModeEnabled(true);
        setPerformanceModeError(
          err instanceof Error ? err.message : 'Failed to load performance mode status'
        );
      } finally {
        if (!cancelled) {
          setPerformanceModeLoading(false);
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!performanceModeEnabled) {
      setPaused(false);
      setBufferedEvents([]);
      setEvents([]);
    }
  }, [performanceModeEnabled]);

  const { connected, error } = useWiretapConnection(
    handleWiretapEvent,
    performanceModeEnabled && !performanceModeLoading
  );

  const filteredEvents = useMemo(
    () => filterWiretapEvents(events, filters),
    [events, filters]
  );

  const aggregated = useMemo(
    () => aggregateWiretapFlows(filteredEvents),
    [filteredEvents]
  );

  const togglePause = () => {
    setPaused((wasPaused) => {
      if (wasPaused) {
        setEvents((prev) => flushBufferedEvents(prev, bufferedEvents, MAX_WIRETAP_EVENTS));
        setBufferedEvents([]);
      }
      return !wasPaused;
    });
  };

  const clear = () => {
    setEvents([]);
    setBufferedEvents([]);
  };

  return {
    events: filteredEvents,
    aggregated,
    filters,
    paused,
    bufferedCount: bufferedEvents.length,
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
  };
}
