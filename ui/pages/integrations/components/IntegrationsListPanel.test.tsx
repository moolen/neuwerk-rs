import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { IntegrationsListPanel } from './IntegrationsListPanel';

describe('IntegrationsListPanel', () => {
  it('renders a simplified configured integrations list without count, selection pills, or auth summary', () => {
    const html = renderToStaticMarkup(
      <IntegrationsListPanel
        loading={false}
        selectedName="homelab"
        onSelect={vi.fn()}
        integrations={[
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
        ]}
      />,
    );

    expect(html).toContain('Configured Integrations');
    expect(html).toContain('homelab');
    expect(html).toContain('API server');
    expect(html).not.toContain('Selected');
    expect(html).not.toContain('Available');
    expect(html).not.toContain('Auth');
    expect(html).not.toContain('class="px-2.5 py-1 rounded-full text-xs font-semibold"');
  });
});
