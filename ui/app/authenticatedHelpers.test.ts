import { describe, expect, it } from 'vitest';

import { authMethodLabel, deriveUserRole } from './authenticatedHelpers';

describe('authenticatedHelpers', () => {
  it('derives user role with readonly precedence', () => {
    expect(deriveUserRole({ sub: 'a', roles: ['admin'] })).toBe('admin');
    expect(deriveUserRole({ sub: 'a', roles: ['admin', 'readonly'] })).toBe('readonly');
  });

  it('formats auth method label', () => {
    expect(authMethodLabel({ sub: 'a', roles: [] })).toBe('jwt');
    expect(authMethodLabel({ sub: 'a', roles: [], sa_id: 'sa-1' })).toBe('service account');
  });
});
