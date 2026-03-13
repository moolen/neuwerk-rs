export interface TlsInterceptCaStatus {
  configured: boolean;
  source?: 'local' | 'cluster' | null;
  fingerprint_sha256?: string | null;
}

export interface PerformanceModeStatus {
  enabled: boolean;
  source?: 'local' | 'cluster' | null;
}
