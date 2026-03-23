import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { SsoProviderView } from '../../../types';
import { SsoProvidersForm } from './SsoProvidersForm';

const provider: SsoProviderView = {
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
  groups_claim: 'groups',
  default_role: 'readonly',
  admin_subjects: ['admin-user'],
  admin_groups: ['admins'],
  admin_email_domains: ['example.com'],
  readonly_subjects: ['readonly-user'],
  readonly_groups: ['readonly-group'],
  readonly_email_domains: ['readonly.example.com'],
  allowed_email_domains: ['example.com'],
  session_ttl_secs: 3600,
};

describe('SsoProvidersForm', () => {
  it('renders progressive disclosure sections while keeping advanced access fields available', () => {
    const html = renderToStaticMarkup(
      <SsoProvidersForm
        providers={[provider]}
        loading={false}
        saving={false}
        deletingId={null}
        testingId={null}
        error={null}
        success={null}
        draft={{
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
          subject_claim: 'sub',
          email_claim: 'email',
          groups_claim: 'groups',
          default_role: 'readonly',
          session_ttl_secs: 3600,
          admin_subjects: 'admin-user',
          admin_groups: 'admins',
          admin_email_domains: 'example.com',
          readonly_subjects: 'readonly-user',
          readonly_groups: 'readonly-group',
          readonly_email_domains: 'readonly.example.com',
          allowed_email_domains: 'example.com',
        }}
        onSelect={() => {}}
        onCreateNew={() => {}}
        onDraftChange={() => {}}
        onSave={() => {}}
        onDelete={() => {}}
        onTest={() => {}}
      />,
    );

    expect(html).toContain('Claim mapping');
    expect(html).toContain('Admin access overrides');
    expect(html).toContain('Readonly access overrides');
    expect(html).toContain('Subject Claim');
    expect(html).toContain('Email Claim');
    expect(html).toContain('Groups Claim');
    expect(html).toContain('Admin Groups');
    expect(html).toContain('Readonly Groups');
  });
});
