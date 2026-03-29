import { jsonResponse } from '../http';
import type { MockRoute } from '../types';
import type { MockState } from '../state';

export function createAuthRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/auth/whoami',
      handler: () => jsonResponse(state.authUser),
    },
    {
      method: 'GET',
      pathname: '/api/v1/auth/sso/providers',
      handler: () => jsonResponse(state.ssoSupportedProviders),
    },
  ];
}
