import React, { useState, useEffect, useRef, useMemo } from 'react';
import { WiretapFilters } from '../components/WiretapFilters';
import { subscribeToWiretap } from '../services/api';
import type { WiretapEvent } from '../types';

const MAX_EVENTS = 500;

type ViewMode = 'live' | 'aggregated';

interface AggregatedFlow {
  key: string;
  src_ip: string;
  dst_ip: string;
  proto: number;
  flow_count: number;
  packets_in: number;
  packets_out: number;
  last_seen: number;
  hostname?: string | null;
}

export const WiretapPage: React.FC = () => {
  const [events, setEvents] = useState<WiretapEvent[]>([]);
  const [bufferedEvents, setBufferedEvents] = useState<WiretapEvent[]>([]);
  const [filters, setFilters] = useState({
    source_ip: '',
    dest_ip: '',
    hostname: '',
    port: '',
  });
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('live');
  const cleanupRef = useRef<(() => void) | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    const connect = () => {
      setError(null);

      const cleanup = subscribeToWiretap(
        (event) => {
          setConnected(true);
          if (paused) {
            setBufferedEvents((prev) => [event, ...prev]);
            return;
          }
          setEvents((prev) => {
            const existingIdx = prev.findIndex((e) => e.flow_id === event.flow_id);
            if (existingIdx >= 0) {
              const updated = [...prev];
              updated[existingIdx] = event;
              return updated;
            }
            const updated = [event, ...prev];
            return updated.slice(0, MAX_EVENTS);
          });
        },
        (err) => {
          setConnected(false);
          setError(err.message);
          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, 5000);
        }
      );

      cleanupRef.current = cleanup;
      setConnected(true);
    };

    connect();

    return () => {
      if (cleanupRef.current) {
        cleanupRef.current();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [paused]);

  const handlePauseToggle = () => {
    if (paused) {
      setEvents((prev) => {
        const merged = [...bufferedEvents, ...prev];
        return merged.slice(0, MAX_EVENTS);
      });
      setBufferedEvents([]);
    }
    setPaused(!paused);
  };

  const handleClear = () => {
    setEvents([]);
    setBufferedEvents([]);
  };

  const filteredEvents = events.filter((event) => {
    if (filters.source_ip && !event.src_ip.toLowerCase().includes(filters.source_ip.toLowerCase())) {
      return false;
    }
    if (filters.dest_ip && !event.dst_ip.toLowerCase().includes(filters.dest_ip.toLowerCase())) {
      return false;
    }
    if (filters.hostname) {
      if (!event.hostname) return false;
      if (!event.hostname.toLowerCase().includes(filters.hostname.toLowerCase())) {
        return false;
      }
    }
    if (filters.port) {
      const portNum = parseInt(filters.port, 10);
      if (isNaN(portNum)) return false;
      if (event.src_port !== portNum && event.dst_port !== portNum) {
        return false;
      }
    }
    return true;
  });

  const aggregated = useMemo(() => {
    const map = new Map<string, AggregatedFlow>();
    for (const event of filteredEvents) {
      const key = `${event.src_ip}|${event.dst_ip}|${event.proto}`;
      const existing = map.get(key);
      if (existing) {
        existing.flow_count += 1;
        existing.packets_in += event.packets_in;
        existing.packets_out += event.packets_out;
        existing.last_seen = Math.max(existing.last_seen, event.last_seen);
        if (event.hostname) existing.hostname = event.hostname;
      } else {
        map.set(key, {
          key,
          src_ip: event.src_ip,
          dst_ip: event.dst_ip,
          proto: event.proto,
          flow_count: 1,
          packets_in: event.packets_in,
          packets_out: event.packets_out,
          last_seen: event.last_seen,
          hostname: event.hostname,
        });
      }
    }
    return Array.from(map.values()).sort((a, b) => b.last_seen - a.last_seen);
  }, [filteredEvents]);

  const formatTimestamp = (ts: number): string => {
    const date = new Date(ts * 1000);
    return date.toLocaleTimeString();
  };

  const protoLabel = (proto: number): string => {
    switch (proto) {
      case 6: return 'tcp';
      case 17: return 'udp';
      case 1: return 'icmp';
      default: return proto.toString();
    }
  };

  return (
    <div className="space-y-4" style={{ color: 'var(--text)' }}>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>Wiretap</h1>
        <div className="flex items-center gap-2 rounded-lg p-1" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <button
            onClick={() => setViewMode('live')}
            className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
            style={viewMode === 'live'
              ? { background: 'var(--accent)', color: 'white' }
              : { color: 'var(--text-muted)' }
            }
          >
            Live
          </button>
          <button
            onClick={() => setViewMode('aggregated')}
            className="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
            style={viewMode === 'aggregated'
              ? { background: 'var(--accent)', color: 'white' }
              : { color: 'var(--text-muted)' }
            }
          >
            Aggregated
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
          <p className="text-sm" style={{ color: 'var(--red)' }}>
            <span className="font-semibold">Connection error:</span> {error}
          </p>
          <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>Reconnecting in 5 seconds...</p>
        </div>
      )}

      {paused && bufferedEvents.length > 0 && (
        <div className="bg-amber-900/50 border border-amber-700 rounded-lg p-3">
          <p className="text-amber-200 text-sm">
            Stream paused — <span className="font-semibold">{bufferedEvents.length}</span> events buffered
          </p>
        </div>
      )}

      <WiretapFilters
        filters={filters}
        onFiltersChange={setFilters}
        paused={paused}
        onPauseToggle={handlePauseToggle}
        onClear={handleClear}
        eventCount={filteredEvents.length}
        connected={connected}
      />

      {viewMode === 'live' ? (
        <div className="rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Flow</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Proto</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Packets In</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Packets Out</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Hostname</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
                    No wiretap events yet.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => (
                  <tr key={event.flow_id} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
                    <td className="py-3 px-4">
                      <div className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}
                      </div>
                      <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{event.node_id}</div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{protoLabel(event.proto)}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{event.packets_in}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{event.packets_out}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{event.hostname || '-'}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(event.last_seen)}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Flow Pair</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Proto</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Flows</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Packets In</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Packets Out</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Hostname</th>
                <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {aggregated.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
                    No aggregated flows yet.
                  </td>
                </tr>
              ) : (
                aggregated.map((flow) => (
                  <tr key={flow.key} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
                    <td className="py-3 px-4">
                      <div className="font-mono text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {flow.src_ip} → {flow.dst_ip}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{protoLabel(flow.proto)}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{flow.flow_count}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{flow.packets_in}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{flow.packets_out}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{flow.hostname || '-'}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(flow.last_seen)}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
