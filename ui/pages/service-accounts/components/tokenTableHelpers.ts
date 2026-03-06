import type { ServiceAccountTokenStatus } from '../../../types';

export function formatTokenTimestamp(value?: string | null): string {
  if (!value) {
    return 'N/A';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'N/A';
  }
  return parsed.toLocaleString();
}

export function canRevokeToken(status: ServiceAccountTokenStatus): boolean {
  return status !== 'revoked';
}
