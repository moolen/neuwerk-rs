import React from 'react';
import { Circle, Pause, Play, Trash2 } from 'lucide-react';

interface WiretapStreamControlsProps {
  paused: boolean;
  connected: boolean;
  eventCount: number;
  onPauseToggle: () => void;
  onClear: () => void;
  disabled?: boolean;
}

export const WiretapStreamControls: React.FC<WiretapStreamControlsProps> = ({
  paused,
  connected,
  eventCount,
  onPauseToggle,
  onClear,
  disabled = false,
}) => (
  <div className="flex items-center justify-between pt-2 border-t border-slate-700">
    <div className="flex items-center space-x-4">
      <button
        onClick={onPauseToggle}
        disabled={disabled}
        className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
          paused
            ? 'bg-amber-600 hover:bg-amber-700 text-white'
            : 'bg-blue-600 hover:bg-blue-700 text-white'
        } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
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

      <button
        onClick={onClear}
        disabled={disabled}
        className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium text-slate-300 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors ${
          disabled ? 'opacity-60 cursor-not-allowed' : ''
        }`}
      >
        <Trash2 className="w-4 h-4" />
        <span>Clear</span>
      </button>
    </div>

    <div className="flex items-center space-x-4">
      <div className="text-sm text-slate-400">
        <span className="font-medium text-white">{eventCount}</span> events
      </div>

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
);
