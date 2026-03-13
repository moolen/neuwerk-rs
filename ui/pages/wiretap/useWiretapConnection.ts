import { useEffect, useRef, useState } from 'react';

import { subscribeToWiretap } from '../../services/api';
import type { WiretapEvent } from '../../types';

interface WiretapConnectionState {
  connected: boolean;
  error: string | null;
}

export function useWiretapConnection(
  onEvent: (event: WiretapEvent) => void,
  streamEnabled: boolean
): WiretapConnectionState {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const onEventRef = useRef(onEvent);

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (!streamEnabled) {
      setConnected(false);
      setError(null);
      return;
    }

    let reconnectTimeout: number | null = null;
    let cleanup: (() => void) | null = null;

    const connect = () => {
      setError(null);
      cleanup = subscribeToWiretap(
        (event) => {
          setConnected(true);
          onEventRef.current(event);
        },
        (streamError) => {
          setConnected(false);
          setError(streamError.message);
          reconnectTimeout = window.setTimeout(() => {
            connect();
          }, 5000);
        },
      );
      setConnected(true);
    };

    connect();

    return () => {
      if (cleanup) {
        cleanup();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, [streamEnabled]);

  return { connected, error };
}
