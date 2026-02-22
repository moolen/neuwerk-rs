import React from 'react';
import { Pause, Play, Trash2, Circle } from 'lucide-react';

interface WiretapFiltersProps {
  filters: {
    source_ip: string;
    dest_ip: string;
    hostname: string;
    port: string;
  };
  onFiltersChange: (filters: WiretapFiltersProps['filters']) => void;
  paused: boolean;
  onPauseToggle: () => void;
  onClear: () => void;
  eventCount: number;
  connected: boolean;
}

export const WiretapFilters: React.FC<WiretapFiltersProps> = ({
  filters,
  onFiltersChange,
  paused,
  onPauseToggle,
  onClear,
  eventCount,
  connected,
}) => {
  const handleFilterChange = (key: keyof typeof filters, value: string) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-4 space-y-4">
      {/* Filter inputs */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div>
          <label htmlFor="source_ip" className="block text-xs font-medium text-slate-400 mb-1">
            Source IP
          </label>
          <input
            id="source_ip"
            type="text"
            value={filters.source_ip}
            onChange={(e) => handleFilterChange('source_ip', e.target.value)}
            placeholder="Filter by source IP"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label htmlFor="dest_ip" className="block text-xs font-medium text-slate-400 mb-1">
            Destination IP
          </label>
          <input
            id="dest_ip"
            type="text"
            value={filters.dest_ip}
            onChange={(e) => handleFilterChange('dest_ip', e.target.value)}
            placeholder="Filter by dest IP"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label htmlFor="hostname" className="block text-xs font-medium text-slate-400 mb-1">
            Hostname
          </label>
          <input
            id="hostname"
            type="text"
            value={filters.hostname}
            onChange={(e) => handleFilterChange('hostname', e.target.value)}
            placeholder="Filter by hostname"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        <div>
          <label htmlFor="port" className="block text-xs font-medium text-slate-400 mb-1">
            Port
          </label>
          <input
            id="port"
            type="text"
            value={filters.port}
            onChange={(e) => handleFilterChange('port', e.target.value)}
            placeholder="Filter by port"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Stream controls */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-700">
        <div className="flex items-center space-x-4">
          {/* Pause/Resume button */}
          <button
            onClick={onPauseToggle}
            className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              paused
                ? 'bg-amber-600 hover:bg-amber-700 text-white'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            }`}
          >
            {paused ? (
              <>
                <Play className="w-4 h-4" />
                <span>Resume</span>
              </>
            ) : (
              <>
                <Pause className="w-4 h-4" />
                <span>Pause</span>
              </>
            )}
          </button>

          {/* Clear button */}
          <button
            onClick={onClear}
            className="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-slate-300 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            <span>Clear</span>
          </button>
        </div>

        <div className="flex items-center space-x-4">
          {/* Event count */}
          <div className="text-sm text-slate-400">
            <span className="font-medium text-white">{eventCount}</span> events
          </div>

          {/* Connection status indicator */}
          <div className="flex items-center space-x-2">
            <Circle
              className={`w-2 h-2 ${
                connected ? 'fill-green-500 text-green-500' : 'fill-red-500 text-red-500'
              }`}
            />
            <span className={`text-xs font-medium ${connected ? 'text-green-400' : 'text-red-400'}`}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
