import { jsonResponse, textResponse } from '../http';
import type { MockState } from '../state';
import type { MockRoute } from '../types';

export function createSettingsReadRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/settings/tls-intercept-ca',
      handler: () => jsonResponse(state.tlsInterceptCaStatus),
    },
    {
      method: 'GET',
      pathname: '/api/v1/settings/tls-intercept-ca/cert',
      handler: () =>
        textResponse(state.tlsInterceptCaCertPem, {
          headers: {
            'content-type': 'application/x-pem-file; charset=utf-8',
          },
        }),
    },
    {
      method: 'GET',
      pathname: '/api/v1/settings/performance-mode',
      handler: () => jsonResponse(state.performanceModeStatus),
    },
    {
      method: 'GET',
      pathname: '/api/v1/settings/threat-intel',
      handler: () => jsonResponse(state.threatIntelSettings),
    },
    {
      method: 'GET',
      pathname: '/api/v1/settings/sso/providers',
      handler: () => jsonResponse(state.ssoProviders),
    },
  ];
}
