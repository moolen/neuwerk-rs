import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ServiceAccount } from '../../types';
import { ServiceAccountTable } from './ServiceAccountTable';

const ACCOUNT: ServiceAccount = {
  id: 'sa-12345678',
  name: 'automation',
  description: 'CI deploy user',
  created_at: '2026-03-22T18:00:00Z',
  created_by: 'ops@example.com',
  role: 'admin',
  status: 'active',
};

describe('ServiceAccountTable', () => {
  it('renders responsive mobile cards alongside desktop table markup', () => {
    const html = renderToStaticMarkup(
      <ServiceAccountTable
        serviceAccounts={[ACCOUNT]}
        onDisable={() => {}}
        onEdit={() => {}}
        onSelectTokens={() => {}}
      />,
    );

    expect(html).toContain('hidden md:block');
    expect(html).toContain('md:hidden');
    expect(html).toContain('Created by');
    expect(html).toContain('Tokens');
  });
});
