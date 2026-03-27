import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRoute } from '../types';

export function createStatsRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/stats',
      handler: () => jsonResponse(state.stats),
    },
  ];
}
