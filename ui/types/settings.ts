import type { ThreatSeverity } from './threats';

export interface TlsInterceptCaStatus {
  configured: boolean;
  source?: 'local' | 'cluster' | null;
  fingerprint_sha256?: string | null;
}

export interface PerformanceModeStatus {
  enabled: boolean;
  source?: 'local' | 'cluster' | null;
}

export interface ThreatFeedToggleStatus {
  enabled: boolean;
  refresh_interval_secs: number;
}

export interface ThreatBaselineFeedsStatus {
  threatfox: ThreatFeedToggleStatus;
  urlhaus: ThreatFeedToggleStatus;
  spamhaus_drop: ThreatFeedToggleStatus;
}

export interface ThreatRemoteEnrichmentSettingsStatus {
  enabled: boolean;
}

export interface ThreatIntelSettingsStatus {
  enabled: boolean;
  alert_threshold: ThreatSeverity;
  baseline_feeds: ThreatBaselineFeedsStatus;
  remote_enrichment: ThreatRemoteEnrichmentSettingsStatus;
  source?: 'local' | 'cluster' | null;
}
