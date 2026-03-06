import type { TlsInterceptCaStatus } from '../../types';
import { fetchJSON, fetchText } from './transport';

export async function getTlsInterceptCaStatus(): Promise<TlsInterceptCaStatus> {
  return fetchJSON<TlsInterceptCaStatus>('/settings/tls-intercept-ca');
}

export async function updateTlsInterceptCa(
  certPem: string,
  keyPem: string
): Promise<TlsInterceptCaStatus> {
  return fetchJSON<TlsInterceptCaStatus>('/settings/tls-intercept-ca', {
    method: 'PUT',
    body: JSON.stringify({
      ca_cert_pem: certPem,
      ca_key_pem: keyPem,
    }),
  });
}

export async function generateTlsInterceptCa(): Promise<TlsInterceptCaStatus> {
  return fetchJSON<TlsInterceptCaStatus>('/settings/tls-intercept-ca/generate', {
    method: 'POST',
  });
}

export async function getTlsInterceptCaCertPem(): Promise<string> {
  return fetchText('/settings/tls-intercept-ca/cert');
}
