import { describe, expect, it } from 'vitest';

import { validateTlsInterceptCaInput } from './helpers';

describe('validateTlsInterceptCaInput', () => {
  it('rejects missing cert pem', () => {
    expect(validateTlsInterceptCaInput('', 'key')).toBe('Certificate PEM and key PEM are required');
  });

  it('rejects missing key pem', () => {
    expect(validateTlsInterceptCaInput('cert', '   ')).toBe('Certificate PEM and key PEM are required');
  });

  it('accepts non-empty cert and key', () => {
    expect(validateTlsInterceptCaInput('cert', 'key')).toBeNull();
  });
});
