import type { AuthUser } from '../types';

export function deriveUserRole(user: AuthUser): 'admin' | 'readonly' {
  return user.roles.includes('readonly') ? 'readonly' : 'admin';
}

export function authMethodLabel(user: AuthUser): string {
  return user.sa_id ? 'service account' : 'jwt';
}
