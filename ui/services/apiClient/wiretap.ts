import type { WiretapEvent } from '../../types';
import { API_BASE } from './transport';

export function subscribeToWiretap(
  onEvent: (event: WiretapEvent) => void,
  onError?: (error: Error) => void
): () => void {
  const streamUrl = `${API_BASE}/wiretap/stream`;
  const eventSource = new EventSource(streamUrl, { withCredentials: true });

  const handler = (e: MessageEvent) => {
    try {
      const event = JSON.parse(e.data);
      onEvent({ ...event, event_type: e.type });
    } catch (err) {
      onError?.(err as Error);
    }
  };

  eventSource.addEventListener('flow', handler as EventListener);
  eventSource.addEventListener('flow_end', handler as EventListener);
  eventSource.onmessage = handler;

  eventSource.onerror = () => {
    onError?.(new Error('Wiretap connection error'));
  };

  return () => eventSource.close();
}
