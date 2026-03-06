import React from 'react';

interface WiretapStatusBannersProps {
  error: string | null;
  paused: boolean;
  bufferedCount: number;
}

export const WiretapStatusBanners: React.FC<WiretapStatusBannersProps> = ({
  error,
  paused,
  bufferedCount,
}) => (
  <>
    {error && (
      <div
        className="rounded-lg p-4"
        style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}
      >
        <p className="text-sm" style={{ color: 'var(--red)' }}>
          <span className="font-semibold">Connection error:</span> {error}
        </p>
        <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>
          Reconnecting in 5 seconds...
        </p>
      </div>
    )}

    {paused && bufferedCount > 0 && (
      <div className="bg-amber-900/50 border border-amber-700 rounded-lg p-3">
        <p className="text-amber-200 text-sm">
          Stream paused - <span className="font-semibold">{bufferedCount}</span> events buffered
        </p>
      </div>
    )}
  </>
);
