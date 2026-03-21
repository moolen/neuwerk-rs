import type {
  PerformanceModeStatus,
  ThreatIntelSettingsStatus,
  TlsInterceptCaStatus,
} from '../../types';
import { fetchBlob, fetchJSON, fetchText } from './transport';

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

export async function getPerformanceModeStatus(): Promise<PerformanceModeStatus> {
  return fetchJSON<PerformanceModeStatus>('/settings/performance-mode');
}

export async function updatePerformanceMode(enabled: boolean): Promise<PerformanceModeStatus> {
  return fetchJSON<PerformanceModeStatus>('/settings/performance-mode', {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });
}

export async function getThreatIntelSettings(): Promise<ThreatIntelSettingsStatus> {
  return fetchJSON<ThreatIntelSettingsStatus>('/settings/threat-intel');
}

export async function updateThreatIntelSettings(
  enabled: boolean
): Promise<ThreatIntelSettingsStatus> {
  return fetchJSON<ThreatIntelSettingsStatus>('/settings/threat-intel', {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });
}

export async function downloadClusterSysdump(): Promise<{
  blob: Blob;
  filename: string | null;
}> {
  return fetchBlob('/support/sysdump/cluster', {
    method: 'POST',
  });
}
