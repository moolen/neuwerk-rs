export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ThreatIndicatorType = 'hostname' | 'ip';
export type ThreatObservationLayer = 'dns' | 'tls' | 'l4';
export type ThreatMatchSource = 'stream' | 'backfill';
export type ThreatEnrichmentStatus =
  | 'not_requested'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed';
export type ThreatRefreshOutcome = 'success' | 'failed' | 'skipped';
export type ThreatSilenceKind = 'exact' | 'hostname_regex';

export interface ThreatFeedIndicatorCounts {
  hostname: number;
  ip: number;
}

export interface ThreatFeedHit {
  feed: string;
  severity: ThreatSeverity;
  confidence?: number | null;
  reference_url?: string | null;
  tags: string[];
}

export interface ThreatFinding {
  indicator: string;
  indicator_type: ThreatIndicatorType;
  observation_layer: ThreatObservationLayer;
  match_source: ThreatMatchSource;
  source_group: string;
  severity: ThreatSeverity;
  confidence?: number | null;
  feed_hits: ThreatFeedHit[];
  first_seen: number;
  last_seen: number;
  count: number;
  sample_node_ids: string[];
  alertable: boolean;
  audit_links: string[];
  enrichment_status: ThreatEnrichmentStatus;
}

export interface ThreatNodeError {
  node_id: string;
  error: string;
}

export interface ThreatFindingQueryResponse {
  items: ThreatFinding[];
  partial: boolean;
  node_errors: ThreatNodeError[];
  nodes_queried: number;
  nodes_responded: number;
  disabled: boolean;
}

export interface ThreatSilenceEntry {
  id: string;
  kind: ThreatSilenceKind;
  indicator_type?: ThreatIndicatorType | null;
  value: string;
  reason?: string | null;
  created_at: number;
  created_by?: string | null;
}

export interface ThreatSilenceListResponse {
  items: ThreatSilenceEntry[];
}

export interface ThreatFeedStatusItem {
  feed: string;
  enabled: boolean;
  snapshot_age_seconds?: number | null;
  last_refresh_started_at?: number | null;
  last_refresh_completed_at?: number | null;
  last_successful_refresh_at?: number | null;
  last_refresh_outcome?: ThreatRefreshOutcome | null;
  indicator_counts: ThreatFeedIndicatorCounts;
}

export interface ThreatFeedStatusResponse {
  snapshot_version: number;
  snapshot_generated_at?: number | null;
  last_refresh_started_at?: number | null;
  last_refresh_completed_at?: number | null;
  last_successful_refresh_at?: number | null;
  last_refresh_outcome?: ThreatRefreshOutcome | null;
  feeds: ThreatFeedStatusItem[];
  disabled: boolean;
}
