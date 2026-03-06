import type { AuthUser } from '../../types';
import {
  API_BASE,
  APIError,
  clearAuthToken,
  extractApiErrorMessage,
  fetchJSON,
} from './transport';

export async function loginWithToken(token: string): Promise<AuthUser> {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new APIError(400, 'Token is required');
  }

  const res = await fetch(`${API_BASE}/auth/token-login`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: trimmed }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new APIError(res.status, extractApiErrorMessage(body, 'Invalid token'));
  }

  return res.json();
}

export async function whoAmI(): Promise<AuthUser> {
  return fetchJSON<AuthUser>('/auth/whoami');
}

export async function logout(): Promise<void> {
  clearAuthToken();
  await fetch(`${API_BASE}/auth/logout`, { method: 'POST', credentials: 'same-origin' }).catch(
    () => undefined
  );
}
