import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRoute } from '../types';

export function createDnsRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/dns-cache',
      handler: () => jsonResponse(state.dnsCache),
    },
  ];
}
