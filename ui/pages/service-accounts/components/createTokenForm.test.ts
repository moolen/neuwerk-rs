import { describe, expect, it } from 'vitest';

import { buildCreateTokenRequest, TOKEN_TTL_PRESETS } from './createTokenForm';

describe('createTokenForm helpers', () => {
  it('defines stable ttl presets', () => {
    expect(TOKEN_TTL_PRESETS).toEqual(['24h', '7d', '30d', '90d']);
  });

  it('builds token request from trimmed inputs', () => {
    expect(buildCreateTokenRequest('  prod-reader  ', ' 90d ', false, 'readonly')).toEqual({
      name: 'prod-reader',
      ttl: '90d',
      eternal: false,
      role: 'readonly',
    });
  });

  it('omits empty optional fields', () => {
    expect(buildCreateTokenRequest('   ', '  ', true, 'admin')).toEqual({
      name: undefined,
      ttl: undefined,
      eternal: true,
      role: 'admin',
    });
  });
});
