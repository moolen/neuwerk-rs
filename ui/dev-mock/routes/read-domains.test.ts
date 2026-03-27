import { describe, expect, it } from 'vitest';

import { createReadDomainRoutes } from '../seed';
import { createMockRouter } from '../router';
import { createMockState } from '../state';

function createTestMockServer() {
  const state = createMockState(1_710_000_000_000);
  const router = createMockRouter({
    routes: createReadDomainRoutes(state),
  });
  return { state, router };
}

describe('dev mock read-domain routes', () => {
  it('returns the seeded preview user', async () => {
    const { router } = createTestMockServer();
    const response = await router.handle({
      method: 'GET',
      url: '/api/v1/auth/whoami',
      headers: {},
      body: undefined,
    });

    expect(response?.status).toBe(200);
    expect(response?.json).toMatchObject({
      sub: 'local-preview-admin',
      roles: ['admin'],
    });
  });

  it('returns seeded read models in expected UI shapes', async () => {
    const { router } = createTestMockServer();
    const [stats, dnsCache, audit, threatFindings, threatFeedStatus, silences, tlsStatus, tlsCert, perf, threatIntel, ssoSupported, ssoProviders] =
      await Promise.all([
        router.handle({ method: 'GET', url: '/api/v1/stats', headers: {}, body: undefined }),
        router.handle({ method: 'GET', url: '/api/v1/dns-cache', headers: {}, body: undefined }),
        router.handle({
          method: 'GET',
          url: '/api/v1/audit/findings?finding_type=dns_deny&source_group=branch-office',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/threats/findings?severity=critical&feed=threatfox&alertable=true',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/threats/feeds/status',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/threats/silences',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/settings/tls-intercept-ca',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/settings/tls-intercept-ca/cert',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/settings/performance-mode',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/settings/threat-intel',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/auth/sso/providers',
          headers: {},
          body: undefined,
        }),
        router.handle({
          method: 'GET',
          url: '/api/v1/settings/sso/providers',
          headers: {},
          body: undefined,
        }),
      ]);

    expect(stats?.status).toBe(200);
    expect(stats?.json).toMatchObject({
      dataplane: expect.any(Object),
      dns: expect.any(Object),
      tls: expect.any(Object),
      dhcp: expect.any(Object),
      cluster: expect.any(Object),
    });

    expect(dnsCache?.status).toBe(200);
    expect(dnsCache?.json).toMatchObject({
      entries: expect.arrayContaining([expect.objectContaining({ hostname: expect.any(String) })]),
    });

    expect(audit?.status).toBe(200);
    expect(audit?.json).toMatchObject({
      partial: expect.any(Boolean),
      node_errors: expect.any(Array),
      nodes_queried: expect.any(Number),
      nodes_responded: expect.any(Number),
      items: expect.arrayContaining([
        expect.objectContaining({
          finding_type: 'dns_deny',
          source_group: 'branch-office',
        }),
      ]),
    });

    expect(threatFindings?.status).toBe(200);
    expect(threatFindings?.json).toMatchObject({
      disabled: expect.any(Boolean),
      partial: expect.any(Boolean),
      node_errors: expect.any(Array),
      items: expect.arrayContaining([
        expect.objectContaining({
          severity: 'critical',
          alertable: true,
        }),
      ]),
    });

    expect(threatFeedStatus?.status).toBe(200);
    expect(threatFeedStatus?.json).toMatchObject({
      feeds: expect.arrayContaining([
        expect.objectContaining({
          feed: expect.any(String),
          indicator_counts: expect.objectContaining({
            hostname: expect.any(Number),
            ip: expect.any(Number),
          }),
        }),
      ]),
      disabled: expect.any(Boolean),
    });

    expect(silences?.status).toBe(200);
    expect(silences?.json).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          id: expect.any(String),
          kind: expect.any(String),
          value: expect.any(String),
        }),
      ]),
    });

    expect(tlsStatus?.status).toBe(200);
    expect(tlsStatus?.json).toMatchObject({
      configured: expect.any(Boolean),
      source: expect.stringMatching(/local|cluster/),
      fingerprint_sha256: expect.any(String),
    });

    expect(tlsCert?.status).toBe(200);
    expect(tlsCert?.kind).toBe('text');
    expect(tlsCert?.text).toContain('BEGIN CERTIFICATE');

    expect(perf?.status).toBe(200);
    expect(perf?.json).toMatchObject({
      enabled: expect.any(Boolean),
      source: expect.stringMatching(/local|cluster/),
    });

    expect(threatIntel?.status).toBe(200);
    expect(threatIntel?.json).toMatchObject({
      enabled: expect.any(Boolean),
      alert_threshold: expect.stringMatching(/low|medium|high|critical/),
      baseline_feeds: expect.objectContaining({
        threatfox: expect.any(Object),
        urlhaus: expect.any(Object),
        spamhaus_drop: expect.any(Object),
      }),
      remote_enrichment: expect.objectContaining({
        enabled: expect.any(Boolean),
      }),
      source: expect.stringMatching(/local|cluster/),
    });

    expect(ssoSupported?.status).toBe(200);
    expect(ssoSupported?.json).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'google' }),
        expect.objectContaining({ id: 'github' }),
        expect.objectContaining({ id: 'generic-oidc' }),
      ])
    );

    expect(ssoProviders?.status).toBe(200);
    expect(ssoProviders?.json).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: expect.any(String),
          name: expect.any(String),
          kind: expect.any(String),
          enabled: expect.any(Boolean),
        }),
      ])
    );
  });
});
