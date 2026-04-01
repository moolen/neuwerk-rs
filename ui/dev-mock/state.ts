import type {
  AuditFinding,
  AuthUser,
  DNSCacheResponse,
  IntegrationView,
  PerformanceModeStatus,
  PolicyRecord,
  ServiceAccount,
  ServiceAccountToken,
  SsoProviderView,
  SsoSupportedProvider,
  StatsResponse,
  ThreatFeedStatusResponse,
  ThreatFinding,
  ThreatIntelSettingsStatus,
  ThreatSilenceEntry,
  TlsInterceptCaStatus,
} from '../types';

export interface MockState {
  authUser: AuthUser;
  stats: StatsResponse;
  dnsCache: DNSCacheResponse;
  auditFindings: AuditFinding[];
  threatFindings: ThreatFinding[];
  threatFeedStatus: ThreatFeedStatusResponse;
  threatSilences: ThreatSilenceEntry[];
  tlsInterceptCaStatus: TlsInterceptCaStatus;
  tlsInterceptCaCertPem: string;
  performanceModeStatus: PerformanceModeStatus;
  threatIntelSettings: ThreatIntelSettingsStatus;
  ssoSupportedProviders: SsoSupportedProvider[];
  ssoProviders: SsoProviderView[];
  policies: PolicyRecord[];
  integrations: IntegrationView[];
  serviceAccounts: ServiceAccount[];
  serviceAccountTokens: Record<string, ServiceAccountToken[]>;
}

export function createMockState(now = Date.now()): MockState {
  const nowSeconds = Math.floor(now / 1000);

  return {
    authUser: {
      sub: 'local-preview-admin',
      roles: ['admin'],
      exp: null,
      sa_id: null,
    },
    stats: {
      dataplane: {
        active_flows: 182,
        active_nat_entries: 97,
        nat_port_utilization: 0.41,
        packets: {
          allow: 1_928_341,
          deny: 4_823,
          pending_tls: 83,
        },
        bytes: {
          allow: 2_145_889_120,
          deny: 13_902_001,
          pending_tls: 1_004_884,
        },
        flows_opened: 22_119,
        flows_closed: 21_937,
        ipv4_fragments_dropped: 11,
        ipv4_ttl_exceeded: 2,
      },
      dns: {
        queries_allow: 8_922,
        queries_deny: 248,
        nxdomain_policy: 39,
        nxdomain_upstream: 126,
      },
      tls: {
        allow: 1_120,
        deny: 47,
      },
      dhcp: {
        lease_active: true,
        lease_expiry_epoch: nowSeconds + 24 * 60 * 60,
      },
      cluster: {
        is_leader: true,
        current_term: 14,
        last_log_index: 8192,
        last_applied: 8192,
        node_count: 3,
        follower_count: 2,
        followers_caught_up: 1,
        nodes: [
          {
            node_id: 'node-a',
            addr: '10.0.10.10:9000',
            role: 'leader',
            matched_index: 8192,
            lag_entries: 0,
            caught_up: true,
          },
          {
            node_id: 'node-b',
            addr: '10.0.10.11:9000',
            role: 'follower',
            matched_index: 8192,
            lag_entries: 0,
            caught_up: true,
          },
          {
            node_id: 'node-c',
            addr: '10.0.10.12:9000',
            role: 'follower',
            matched_index: 8179,
            lag_entries: 13,
            caught_up: false,
          },
        ],
      },
    },
    dnsCache: {
      entries: [
        {
          hostname: 'api.github.com',
          ips: ['140.82.112.5'],
          last_seen: nowSeconds - 65,
        },
        {
          hostname: 'pkg.neuwerk.internal',
          ips: ['10.20.4.8', '10.20.4.9'],
          last_seen: nowSeconds - 90,
        },
        {
          hostname: 'cdn.example.net',
          ips: ['198.51.100.40'],
          last_seen: nowSeconds - 320,
        },
      ],
    },
    auditFindings: [
      {
        finding_type: 'dns_deny',
        policy_id: 'policy-egress-dns',
        source_group: 'branch-office',
        hostname: 'malware-update.bad',
        query_type: 1,
        first_seen: nowSeconds - 3_000,
        last_seen: nowSeconds - 120,
        count: 17,
        node_ids: ['node-a', 'node-c'],
      },
      {
        finding_type: 'tls_deny',
        policy_id: 'policy-tls-exceptions',
        source_group: 'finance',
        sni: 'suspicious-tls.invalid',
        dst_ip: '203.0.113.45',
        dst_port: 443,
        first_seen: nowSeconds - 8_000,
        last_seen: nowSeconds - 420,
        count: 4,
        node_ids: ['node-b'],
      },
      {
        finding_type: 'l4_deny',
        policy_id: null,
        source_group: 'iot-segment',
        dst_ip: '198.51.100.32',
        dst_port: 23,
        proto: 6,
        first_seen: nowSeconds - 20_000,
        last_seen: nowSeconds - 900,
        count: 21,
        node_ids: ['node-c'],
      },
    ],
    threatFindings: [
      {
        indicator: 'evil-control.example',
        indicator_type: 'hostname',
        observation_layer: 'dns',
        match_source: 'stream',
        source_group: 'branch-office',
        severity: 'critical',
        confidence: 0.95,
        feed_hits: [
          {
            feed: 'threatfox',
            severity: 'critical',
            confidence: 0.92,
            reference_url: 'https://example.invalid/threatfox/evil-control',
            tags: ['c2', 'botnet'],
          },
        ],
        first_seen: nowSeconds - 3_600,
        last_seen: nowSeconds - 180,
        count: 9,
        sample_node_ids: ['node-a'],
        alertable: true,
        audit_links: ['dns:policy-egress-dns:branch-office:malware-update.bad'],
        enrichment_status: 'completed',
      },
      {
        indicator: '198.51.100.77',
        indicator_type: 'ip',
        observation_layer: 'l4',
        match_source: 'backfill',
        source_group: 'finance',
        severity: 'high',
        confidence: 0.78,
        feed_hits: [
          {
            feed: 'spamhaus_drop',
            severity: 'high',
            tags: ['drop-list'],
          },
        ],
        first_seen: nowSeconds - 12_000,
        last_seen: nowSeconds - 900,
        count: 3,
        sample_node_ids: ['node-b'],
        alertable: false,
        audit_links: [],
        enrichment_status: 'not_requested',
      },
      {
        indicator: 'compromised-login.example',
        indicator_type: 'hostname',
        observation_layer: 'tls',
        match_source: 'stream',
        source_group: 'engineering',
        severity: 'medium',
        confidence: 0.61,
        feed_hits: [
          {
            feed: 'urlhaus',
            severity: 'medium',
            tags: ['phishing'],
          },
        ],
        first_seen: nowSeconds - 18_000,
        last_seen: nowSeconds - 1_200,
        count: 12,
        sample_node_ids: ['node-c'],
        alertable: true,
        audit_links: [],
        enrichment_status: 'queued',
      },
    ],
    threatFeedStatus: {
      snapshot_version: 42,
      snapshot_generated_at: nowSeconds - 90,
      last_refresh_started_at: nowSeconds - 120,
      last_refresh_completed_at: nowSeconds - 90,
      last_successful_refresh_at: nowSeconds - 90,
      last_refresh_outcome: 'success',
      disabled: false,
      feeds: [
        {
          feed: 'threatfox',
          enabled: true,
          snapshot_age_seconds: 90,
          last_refresh_started_at: nowSeconds - 120,
          last_refresh_completed_at: nowSeconds - 90,
          last_successful_refresh_at: nowSeconds - 90,
          last_refresh_outcome: 'success',
          indicator_counts: {
            hostname: 820,
            ip: 1_204,
          },
        },
        {
          feed: 'urlhaus',
          enabled: true,
          snapshot_age_seconds: 150,
          last_refresh_started_at: nowSeconds - 180,
          last_refresh_completed_at: nowSeconds - 150,
          last_successful_refresh_at: nowSeconds - 150,
          last_refresh_outcome: 'success',
          indicator_counts: {
            hostname: 442,
            ip: 97,
          },
        },
        {
          feed: 'spamhaus_drop',
          enabled: false,
          snapshot_age_seconds: 9_400,
          last_refresh_started_at: nowSeconds - 9_430,
          last_refresh_completed_at: nowSeconds - 9_400,
          last_successful_refresh_at: nowSeconds - 86_400,
          last_refresh_outcome: 'failed',
          indicator_counts: {
            hostname: 0,
            ip: 388,
          },
        },
      ],
    },
    threatSilences: [
      {
        id: 'silence-001',
        kind: 'exact',
        indicator_type: 'hostname',
        value: 'partner-updates.example',
        reason: 'approved partner telemetry endpoint',
        created_at: nowSeconds - 3600,
        created_by: 'local-preview-admin',
      },
      {
        id: 'silence-002',
        kind: 'hostname_regex',
        indicator_type: 'hostname',
        value: '.*\\.corp-neuwerk\\.example$',
        reason: 'internal test domains',
        created_at: nowSeconds - 172_800,
        created_by: 'local-preview-admin',
      },
    ],
    tlsInterceptCaStatus: {
      configured: true,
      source: 'cluster',
      fingerprint_sha256: '5f:88:4c:c2:72:a1:db:5c:55:e4:31:75:3a:3a:b8:3f:9d:9b:84:5a:d4:d5:ad:11:a7:9b:8f:f0:1a:77:d8:21',
    },
    tlsInterceptCaCertPem: [
      '-----BEGIN CERTIFICATE-----',
      'MIIC3jCCAcagAwIBAgIUFx0aW4Qq14+W2CQl9Q9fjdP4v1EwDQYJKoZIhvcNAQEL',
      'BQAwHDEaMBgGA1UEAwwRTmV1d2VyayBEZXYgUm9vdDAeFw0yNTAxMDEwMDAwMDBa',
      'Fw0zNTAxMDEwMDAwMDBaMBwxGjAYBgNVBAMMEU5ldXdlcmsgRGV2IFJvb3QwggEi',
      'MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4smockedpreviewcertmaterial',
      '-----END CERTIFICATE-----',
      '',
    ].join('\n'),
    performanceModeStatus: {
      enabled: true,
      source: 'cluster',
    },
    threatIntelSettings: {
      enabled: true,
      alert_threshold: 'high',
      baseline_feeds: {
        threatfox: {
          enabled: true,
          refresh_interval_secs: 900,
        },
        urlhaus: {
          enabled: true,
          refresh_interval_secs: 1_800,
        },
        spamhaus_drop: {
          enabled: false,
          refresh_interval_secs: 3_600,
        },
      },
      remote_enrichment: {
        enabled: false,
      },
      source: 'cluster',
    },
    ssoSupportedProviders: [
      { id: 'google', name: 'Google Workspace', kind: 'google' },
      { id: 'github', name: 'GitHub', kind: 'github' },
      { id: 'generic-oidc', name: 'OpenID Connect', kind: 'generic-oidc' },
    ],
    ssoProviders: [
      {
        id: 'sso-provider-001',
        created_at: '2026-03-20T10:12:00.000Z',
        updated_at: '2026-03-26T08:45:00.000Z',
        name: 'Corporate Entra ID',
        kind: 'generic-oidc',
        enabled: true,
        display_order: 0,
        issuer_url: 'https://login.microsoftonline.com/example/v2.0',
        authorization_url: null,
        token_url: null,
        userinfo_url: null,
        client_id: 'neuwerk-preview-client',
        client_secret_configured: true,
        scopes: ['openid', 'profile', 'email', 'groups'],
        pkce_required: true,
        subject_claim: 'sub',
        email_claim: 'email',
        groups_claim: 'groups',
        default_role: 'readonly',
        admin_subjects: ['admin@example.com'],
        admin_groups: ['network-admins'],
        admin_email_domains: ['example.com'],
        readonly_subjects: [],
        readonly_groups: ['network-readers'],
        readonly_email_domains: ['contractor.example'],
        allowed_email_domains: ['example.com', 'contractor.example'],
        session_ttl_secs: 28_800,
      },
    ],
    policies: [
      {
        id: 'singleton',
        created_at: new Date(now).toISOString(),
        mode: 'enforce',
        policy: {
          default_policy: 'deny',
          source_groups: [],
        },
      },
    ],
    integrations: [],
    serviceAccounts: [],
    serviceAccountTokens: {},
  };
}
