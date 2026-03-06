import type { WiretapEvent } from '../../types';

export interface WiretapFiltersState {
  source_ip: string;
  dest_ip: string;
  hostname: string;
  port: string;
}

export function defaultWiretapFilters(): WiretapFiltersState {
  return {
    source_ip: '',
    dest_ip: '',
    hostname: '',
    port: '',
  };
}

export function upsertWiretapEvent(
  events: WiretapEvent[],
  event: WiretapEvent,
  maxEvents: number,
): WiretapEvent[] {
  const existingIdx = events.findIndex((item) => item.flow_id === event.flow_id);
  if (existingIdx >= 0) {
    const updated = [...events];
    updated[existingIdx] = event;
    return updated;
  }
  return [event, ...events].slice(0, maxEvents);
}

export function flushBufferedEvents(
  events: WiretapEvent[],
  bufferedEvents: WiretapEvent[],
  maxEvents: number,
): WiretapEvent[] {
  return [...bufferedEvents, ...events].slice(0, maxEvents);
}
