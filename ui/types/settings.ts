export interface TlsInterceptCaStatus {
  configured: boolean;
  source?: 'local' | 'cluster' | null;
  fingerprint_sha256?: string | null;
}
