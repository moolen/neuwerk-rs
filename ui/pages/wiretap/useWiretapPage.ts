import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { WiretapEvent } from '../../types';
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

  const { connected, error } = useWiretapConnection(handleWiretapEvent);

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
    viewMode,
    setViewMode,
    setFilters,
    togglePause,
    clear,
  };
}
