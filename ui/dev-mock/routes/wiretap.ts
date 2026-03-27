import type { WiretapEvent } from '../../types';
import { sseStreamResponse } from '../http';
import type { MockRoute } from '../types';

const EVENT_INTERVAL_MS = 3_000;

const SAMPLE_FLOWS: WiretapEvent[] = [
  {
    flow_id: 'flow-1',
    src_ip: '10.10.10.10',
    dst_ip: '93.184.216.34',
    src_port: 53422,
    dst_port: 443,
    proto: 6,
    packets_in: 18,
    packets_out: 11,
    last_seen: 0,
    hostname: 'example.com',
    node_id: 'neuwerk-node-a',
  },
  {
    flow_id: 'flow-2',
    src_ip: '10.10.10.11',
    dst_ip: '1.1.1.1',
    src_port: 39910,
    dst_port: 53,
    proto: 17,
    packets_in: 5,
    packets_out: 5,
    last_seen: 0,
    hostname: 'cloudflare-dns.com',
    node_id: 'neuwerk-node-b',
  },
  {
    flow_id: 'flow-3',
    src_ip: '10.10.10.12',
    dst_ip: '142.250.74.46',
    src_port: 50100,
    dst_port: 443,
    proto: 6,
    packets_in: 27,
    packets_out: 30,
    last_seen: 0,
    hostname: 'google.com',
    node_id: 'neuwerk-node-a',
  },
];

function encodeEvent(eventType: 'flow' | 'flow_end', payload: WiretapEvent): string {
  return `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function withTimestamp(event: WiretapEvent): WiretapEvent {
  return {
    ...event,
    last_seen: Date.now(),
  };
}

export function createWiretapRoutes(): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/wiretap/stream',
      handler: () =>
        sseStreamResponse((req, res) => {
          let index = 0;
          let interval: ReturnType<typeof setInterval> | undefined;
          const isClosed = () => res.destroyed || res.writableEnded;

          const cleanup = () => {
            if (interval) {
              clearInterval(interval);
              interval = undefined;
            }
            req.off('close', cleanup);
            res.off('close', cleanup);
            res.off('error', cleanup);
            if (!isClosed()) {
              res.end();
            }
          };

          const writeSample = () => {
            if (isClosed()) {
              cleanup();
              return;
            }
            const base = withTimestamp(SAMPLE_FLOWS[index % SAMPLE_FLOWS.length]);
            const flow = base;
            const flowEnd = withTimestamp({
              ...base,
              packets_in: base.packets_in + 1,
              packets_out: base.packets_out + 2,
            });
            res.write(encodeEvent('flow', flow));
            res.write(encodeEvent('flow_end', flowEnd));
            index += 1;
          };

          writeSample();
          interval = setInterval(writeSample, EVENT_INTERVAL_MS);

          req.on('close', cleanup);
          res.on('close', cleanup);
          res.on('error', cleanup);
        }),
    },
  ];
}
