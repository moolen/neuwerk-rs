import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { IntegrationsPage } from '../../IntegrationsPage';
import { useIntegrationsPage } from '../useIntegrationsPage';

vi.mock('../useIntegrationsPage', () => ({
  useIntegrationsPage: vi.fn(),
}));

describe('IntegrationsPage structure', () => {
  beforeEach(() => {
    vi.mocked(useIntegrationsPage).mockReturnValue({
      integrations: [
        {
          id: 'integration-1',
          created_at: '2026-03-22T08:00:00Z',
          name: 'homelab',
          kind: 'kubernetes',
          api_server_url: 'https://192.168.178.149:6443',
          ca_cert_pem: '-----BEGIN CERTIFICATE-----',
          auth_type: 'service_account_token',
          token_configured: true,
        },
      ],
      selectedName: 'homelab',
      editorMode: 'edit',
      form: {
        name: 'homelab',
        kind: 'kubernetes',
        apiServerUrl: 'https://192.168.178.149:6443',
        caCertPem: '-----BEGIN CERTIFICATE-----',
        serviceAccountToken: '',
      },
      loading: false,
      saving: false,
      error: null,
      editorError: null,
      loadIntegrations: async () => {},
      selectIntegration: async () => {},
      createNewIntegration: () => {},
      saveIntegration: async () => {},
      deleteSelectedIntegration: async () => {},
      setFormField: () => {},
    });
  });

  it('renders summary cues and labeled editor sections', () => {
    const html = renderToStaticMarkup(<IntegrationsPage />);

    expect(html).toContain('Configured');
    expect(html).toContain('Selection');
    expect(html).toContain('Connection Profile');
    expect(html).toContain('Credentials');
    expect(html).toContain('xl:grid-cols-[minmax(18rem,22rem)_minmax(0,1fr)]');
  });
});
