import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { IntegrationView, PolicyKubernetesSource } from '../../../types';
import { KubernetesSourceIntegrationRow } from './KubernetesSourceIntegrationRow';

describe('KubernetesSourceIntegrationRow', () => {
  it('renders the integration picker with the custom dropdown instead of a native select', () => {
    const source: PolicyKubernetesSource = {
      integration: 'cluster-a',
    };
    const integrations: IntegrationView[] = [
      {
        id: 'integration-1',
        created_at: '2026-03-23T00:00:00Z',
        name: 'cluster-a',
        kind: 'kubernetes',
        api_server_url: 'https://cluster-a.internal',
        ca_cert_pem: 'pem',
        auth_type: 'token',
        token_configured: true,
      },
    ];

    const html = renderToStaticMarkup(
      <KubernetesSourceIntegrationRow
        groupIndex={0}
        sourceIndex={0}
        source={source}
        integrations={integrations}
        updateDraft={vi.fn()}
      />,
    );

    expect(html).toContain('data-custom-select-trigger="true"');
    expect(html).toContain('cluster-a');
    expect(html).not.toContain('<select');
  });
});
