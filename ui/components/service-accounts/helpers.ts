import type { ServiceAccount, ServiceAccountRole } from '../../types';

export function formatServiceAccountTimestamp(timestamp?: string): string {
  if (!timestamp) return 'N/A';
  try {
    const date = new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return 'N/A';
  }
}

export function serviceAccountStatusLabel(status: ServiceAccount['status']): string {
  return status === 'active' ? 'Active' : 'Disabled';
}

export function serviceAccountStatusStyle(status: ServiceAccount['status']) {
  if (status === 'active') {
    return {
      background: 'var(--green-bg)',
      color: 'var(--green)',
      border: '1px solid var(--green-border)',
    };
  }
  return {
    background: 'var(--red-bg)',
    color: 'var(--red)',
    border: '1px solid var(--red-border)',
  };
}

export function serviceAccountRoleLabel(role: ServiceAccountRole): string {
  return role === 'admin' ? 'Admin' : 'Readonly';
}

export function serviceAccountRoleStyle(role: ServiceAccountRole) {
  if (role === 'admin') {
    return {
      background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
      color: 'var(--accent)',
      border: '1px solid color-mix(in srgb, var(--accent) 40%, transparent)',
    };
  }
  return {
    background: 'var(--bg-input)',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border-subtle)',
  };
}

export function isServiceAccountRoleDowngrade(
  currentRole: ServiceAccountRole,
  nextRole: ServiceAccountRole
): boolean {
  return currentRole === 'admin' && nextRole === 'readonly';
}
