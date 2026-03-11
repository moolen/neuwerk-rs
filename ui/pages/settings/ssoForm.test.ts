import { describe, expect, it } from 'vitest';

import {
  buildSsoCreateRequest,
  buildSsoPatchRequest,
  emptySsoProviderDraft,
  validateSsoProviderDraft,
} from './ssoForm';

describe('validateSsoProviderDraft', () => {
  it('requires name and client id', () => {
    const draft = emptySsoProviderDraft();
    expect(validateSsoProviderDraft(draft)).toBe('Provider name is required');

    draft.name = 'Test';
    expect(validateSsoProviderDraft(draft)).toBe('Client ID is required');
  });

  it('requires secret for new providers', () => {
    const draft = emptySsoProviderDraft();
    draft.name = 'Test';
    draft.client_id = 'cid';
    expect(validateSsoProviderDraft(draft)).toBe('Client secret is required for new providers');
  });

  it('accepts update without secret', () => {
    const draft = emptySsoProviderDraft();
    draft.id = 'provider-1';
    draft.name = 'Test';
    draft.client_id = 'cid';
    expect(validateSsoProviderDraft(draft)).toBeNull();
  });
});

describe('ssoForm payload builders', () => {
  it('normalizes create payload list fields', () => {
    const draft = emptySsoProviderDraft();
    draft.name = ' Google ';
    draft.client_id = ' cid ';
    draft.client_secret = ' secret ';
    draft.scopes = 'openid, email,  profile';

    const payload = buildSsoCreateRequest(draft);
    expect(payload.name).toBe('Google');
    expect(payload.client_id).toBe('cid');
    expect(payload.client_secret).toBe('secret');
    expect(payload.scopes).toEqual(['openid', 'email', 'profile']);
  });

  it('omits empty patch client_secret', () => {
    const draft = emptySsoProviderDraft();
    draft.id = 'provider-1';
    draft.name = 'Update';
    draft.client_id = 'cid';

    const payload = buildSsoPatchRequest(draft);
    expect(payload.client_secret).toBeUndefined();

    draft.client_secret = ' next ';
    const withSecret = buildSsoPatchRequest(draft);
    expect(withSecret.client_secret).toBe('next');
  });
});
