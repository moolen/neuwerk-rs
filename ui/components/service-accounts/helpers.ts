import type { ServiceAccount } from '../../types';

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
