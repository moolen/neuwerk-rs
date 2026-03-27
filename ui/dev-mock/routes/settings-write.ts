import { createHash } from 'node:crypto';

import { blobResponse, jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRequest, MockRoute } from '../types';

function parseJsonBody(request: MockRequest): unknown {
  if (!request.body || request.body.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(request.body.toString('utf-8'));
  } catch {
    return undefined;
  }
}

function formatFingerprint(input: string): string {
  const hex = createHash('sha256').update(input).digest('hex');
  const pairs = hex.match(/.{1,2}/g) ?? [];
  return pairs.join(':');
}

function createGeneratedCaPem(): string {
  const stamp = new Date().toISOString();
  return [
    '-----BEGIN CERTIFICATE-----',
    Buffer.from(`neuwerk-mock-ca:${stamp}`).toString('base64'),
    '-----END CERTIFICATE-----',
    '',
  ].join('\n');
}

export function createSettingsWriteRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'PUT',
      pathname: '/api/v1/settings/tls-intercept-ca',
      handler: (request) => {
        const payload = parseJsonBody(request) as
          | { ca_cert_pem?: string; ca_key_pem?: string }
          | undefined;
        const certPem = payload?.ca_cert_pem?.trim() ?? '';
        const keyPem = payload?.ca_key_pem?.trim() ?? '';
        if (!certPem || !keyPem) {
          return jsonResponse(
            { error: 'ca_cert_pem and ca_key_pem are required' },
            { status: 400 }
          );
        }

        state.tlsInterceptCaCertPem = certPem.endsWith('\n') ? certPem : `${certPem}\n`;
        state.tlsInterceptCaStatus = {
          configured: true,
          source: 'local',
          fingerprint_sha256: formatFingerprint(`${certPem}\n${keyPem}`),
        };
        return jsonResponse(state.tlsInterceptCaStatus);
      },
    },
    {
      method: 'POST',
      pathname: '/api/v1/settings/tls-intercept-ca/generate',
      handler: () => {
        const certPem = createGeneratedCaPem();
        state.tlsInterceptCaCertPem = certPem;
        state.tlsInterceptCaStatus = {
          configured: true,
          source: 'local',
          fingerprint_sha256: formatFingerprint(certPem),
        };
        return jsonResponse(state.tlsInterceptCaStatus);
      },
    },
    {
      method: 'PUT',
      pathname: '/api/v1/settings/performance-mode',
      handler: (request) => {
        const payload = parseJsonBody(request) as { enabled?: boolean } | undefined;
        if (typeof payload?.enabled !== 'boolean') {
          return jsonResponse({ error: 'enabled must be boolean' }, { status: 400 });
        }
        state.performanceModeStatus = {
          ...state.performanceModeStatus,
          enabled: payload.enabled,
          source: 'local',
        };
        return jsonResponse(state.performanceModeStatus);
      },
    },
    {
      method: 'PUT',
      pathname: '/api/v1/settings/threat-intel',
      handler: (request) => {
        const payload = parseJsonBody(request) as { enabled?: boolean } | undefined;
        if (typeof payload?.enabled !== 'boolean') {
          return jsonResponse({ error: 'enabled must be boolean' }, { status: 400 });
        }
        state.threatIntelSettings = {
          ...state.threatIntelSettings,
          enabled: payload.enabled,
          source: 'local',
        };
        return jsonResponse(state.threatIntelSettings);
      },
    },
    {
      method: 'POST',
      pathname: '/api/v1/support/sysdump/cluster',
      handler: () => {
        const now = new Date();
        const filename = `neuwerk-cluster-sysdump-${now
          .toISOString()
          .replace(/[:.]/g, '-')}.tar.gz`;
        const body = Buffer.from(
          `mock cluster sysdump generated at ${now.toISOString()}\n`,
          'utf-8'
        );
        return blobResponse(body, {
          headers: {
            'content-type': 'application/gzip',
            'content-disposition': `attachment; filename="${filename}"`,
          },
        });
      },
    },
  ];
}
