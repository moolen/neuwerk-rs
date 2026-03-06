import { describe, expect, it } from 'vitest';

import { formatServiceAccountTimestamp, serviceAccountStatusLabel, serviceAccountStatusStyle } from './helpers';

describe('service account helpers', () => {
  it('formats missing timestamps as N/A', () => {
    expect(formatServiceAccountTimestamp()).toBe('N/A');
  });

  it('returns status label and style for active status', () => {
    expect(serviceAccountStatusLabel('active')).toBe('Active');
    expect(serviceAccountStatusStyle('active')).toMatchObject({
      color: 'var(--green)',
    });
  });

  it('returns status label and style for disabled status', () => {
    expect(serviceAccountStatusLabel('disabled')).toBe('Disabled');
    expect(serviceAccountStatusStyle('disabled')).toMatchObject({
      color: 'var(--red)',
    });
  });
});
