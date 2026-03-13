import { describe, expect, it } from 'vitest';

import {
  formatServiceAccountTimestamp,
  isServiceAccountRoleDowngrade,
  serviceAccountRoleLabel,
  serviceAccountRoleStyle,
  serviceAccountStatusLabel,
  serviceAccountStatusStyle,
} from './helpers';

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

  it('returns role label and style for readonly and admin', () => {
    expect(serviceAccountRoleLabel('readonly')).toBe('Readonly');
    expect(serviceAccountRoleLabel('admin')).toBe('Admin');
    expect(serviceAccountRoleStyle('readonly')).toMatchObject({
      color: 'var(--text-secondary)',
    });
    expect(serviceAccountRoleStyle('admin')).toMatchObject({
      color: 'var(--accent)',
    });
  });

  it('detects only admin to readonly as a downgrade', () => {
    expect(isServiceAccountRoleDowngrade('admin', 'readonly')).toBe(true);
    expect(isServiceAccountRoleDowngrade('readonly', 'admin')).toBe(false);
    expect(isServiceAccountRoleDowngrade('admin', 'admin')).toBe(false);
  });
});
