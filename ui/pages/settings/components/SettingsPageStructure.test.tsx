import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SettingsPage } from '../../SettingsPage';
import { useSettingsPage } from '../useSettingsPage';

vi.mock('../useSettingsPage', () => ({
  useSettingsPage: vi.fn(),
}));

describe('SettingsPage structure', () => {
  beforeEach(() => {
    vi.mocked(useSettingsPage).mockReturnValue({
      status: {
        configured: true,
        source: 'cluster',
        fingerprint_sha256: '757970318ee2c36c1e7b45314b64e689403473c5f7fd9ad4a55a6c0831e0ed3b',
      },
      performanceMode: {
        enabled: true,
        source: 'cluster',
      },
      threatSettings: {
        enabled: true,
        alert_threshold: 'high',
        baseline_feeds: {
          threatfox: { enabled: true, refresh_interval_secs: 3600 },
          urlhaus: { enabled: true, refresh_interval_secs: 3600 },
          spamhaus_drop: { enabled: true, refresh_interval_secs: 3600 },
        },
        remote_enrichment: { enabled: false },
        source: 'cluster',
      },
      loading: false,
      performanceModeSaving: false,
      threatSettingsSaving: false,
      saving: false,
      generating: false,
      downloading: false,
      error: null,
      success: null,
      certPem: '',
      keyPem: '',
      setCertPem: () => {},
      setKeyPem: () => {},
      refresh: async () => {},
      submit: async () => {},
      generate: async () => {},
      downloadCert: async () => {},
      sysdumpDownloading: false,
      downloadClusterBundle: async () => {},
      savePerformanceMode: async () => {},
      saveThreatAnalysisEnabled: async () => {},
      ssoProviders: [
        {
          id: 'provider-1',
          created_at: '2026-03-22T08:00:00Z',
          updated_at: '2026-03-22T08:00:00Z',
          name: 'GitHub',
          kind: 'github',
          enabled: true,
          display_order: 1,
          issuer_url: 'https://github.com',
          authorization_url: 'https://github.com/login/oauth/authorize',
          token_url: 'https://github.com/login/oauth/access_token',
          userinfo_url: 'https://api.github.com/user',
          client_id: 'client-id',
          client_secret_configured: true,
          scopes: ['read:user'],
          pkce_required: false,
          subject_claim: 'sub',
          email_claim: 'email',
          groups_claim: null,
          default_role: 'readonly',
          admin_subjects: [],
          admin_groups: [],
          admin_email_domains: ['example.com'],
          readonly_subjects: [],
          readonly_groups: [],
          readonly_email_domains: ['example.com'],
          allowed_email_domains: ['example.com'],
          session_ttl_secs: 3600,
        },
      ],
      ssoLoading: false,
      ssoSaving: false,
      ssoDeletingId: null,
      ssoTestingId: null,
      ssoError: null,
      ssoSuccess: null,
      ssoDraft: {
        id: 'provider-1',
        name: 'GitHub',
        kind: 'github',
        enabled: true,
        display_order: 1,
        issuer_url: 'https://github.com',
        authorization_url: 'https://github.com/login/oauth/authorize',
        token_url: 'https://github.com/login/oauth/access_token',
        userinfo_url: 'https://api.github.com/user',
        client_id: 'client-id',
        client_secret: '',
        scopes: 'read:user',
        pkce_required: false,
        subject_claim: 'sub',
        email_claim: 'email',
        groups_claim: '',
        default_role: 'readonly',
        admin_subjects: '',
        admin_groups: '',
        admin_email_domains: 'example.com',
        readonly_subjects: '',
        readonly_groups: '',
        readonly_email_domains: 'example.com',
        allowed_email_domains: 'example.com',
        session_ttl_secs: 3600,
      },
      setSsoDraft: () => {},
      createNewSsoDraft: () => {},
      selectSsoProvider: () => {},
      saveSsoProviderDraft: async () => {},
      deleteSsoProviderById: async () => {},
      testSsoProviderById: async () => {},
    });
  });

  it('renders grouped settings landmarks for scanning', () => {
    const html = renderToStaticMarkup(<SettingsPage />);

    expect(html).toContain('Control plane posture');
    expect(html).toContain('TLS intercept readiness');
    expect(html).toContain('Trust material');
    expect(html).toContain('Identity providers');
    expect(html).toContain('xl:grid-cols-[minmax(0,1.7fr)_minmax(20rem,0.9fr)]');
  });
});
