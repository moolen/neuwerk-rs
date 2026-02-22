import type {
  StatsResponse,
  DNSCacheResponse,
  PolicyRecord,
  PolicyCreateRequest,
  AuthUser,
  ServiceAccount,
  ServiceAccountToken,
  CreateServiceAccountRequest,
  CreateServiceAccountTokenRequest,
  CreateServiceAccountTokenResponse,
} from '../types';

const API_BASE = '/api/v1';
const TOKEN_KEY = 'neuwerk_api_token';

let inMemoryToken: string | null = null;

class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'APIError';
  }
}

function loadStoredToken(): string | null {
  if (inMemoryToken) return inMemoryToken;
  if (typeof window === 'undefined') return null;
  try {
    const token = window.localStorage.getItem(TOKEN_KEY);
    inMemoryToken = token;
    return token;
  } catch {
    return null;
  }
}

export function setAuthToken(token: string) {
  inMemoryToken = token;
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Ignore storage failures
  }
}

export function clearAuthToken() {
  inMemoryToken = null;
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Ignore storage failures
  }
}

export function getAuthToken(): string | null {
  return loadStoredToken();
}

async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  const token = getAuthToken();
  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    throw new APIError(res.status, body.message || res.statusText);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

async function fetchText(path: string, options?: RequestInit): Promise<string> {
  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string>),
  };

  const token = getAuthToken();
  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => res.statusText);
    throw new APIError(res.status, body || res.statusText);
  }

  return res.text();
}

// Authentication
export async function loginWithToken(token: string): Promise<AuthUser> {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new APIError(400, 'Token is required');
  }

  const res = await fetch(`${API_BASE}/auth/token-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: trimmed }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ message: res.statusText }));
    throw new APIError(res.status, body.message || 'Invalid token');
  }

  const user = await res.json();
  setAuthToken(trimmed);
  return user;
}

export async function whoAmI(): Promise<AuthUser> {
  return fetchJSON<AuthUser>('/auth/whoami');
}

export async function logout(): Promise<void> {
  clearAuthToken();
  await fetch(`${API_BASE}/auth/logout`, { method: 'POST' }).catch(() => undefined);
}

// Stats
export async function getStats(): Promise<StatsResponse> {
  return fetchJSON<StatsResponse>('/stats');
}

// Policies
export async function listPolicies(): Promise<PolicyRecord[]> {
  return fetchJSON<PolicyRecord[]>('/policies');
}

export async function getPolicy(id: string): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>(`/policies/${encodeURIComponent(id)}`);
}

export async function getPolicyYaml(id: string): Promise<string> {
  return fetchText(`/policies/${encodeURIComponent(id)}?format=yaml`);
}

export async function createPolicy(req: PolicyCreateRequest): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>('/policies', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function updatePolicy(id: string, req: PolicyCreateRequest): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>(`/policies/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(req),
  });
}

export async function deletePolicy(id: string): Promise<void> {
  await fetchJSON<void>(`/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// DNS Cache
export async function getDNSCache(): Promise<DNSCacheResponse> {
  return fetchJSON<DNSCacheResponse>('/dns-cache');
}

// Wiretap SSE
export function subscribeToWiretap(
  onEvent: (event: import('../types').WiretapEvent) => void,
  onError?: (error: Error) => void
): () => void {
  const eventSource = new EventSource(`${API_BASE}/wiretap/stream`);

  const handler = (e: MessageEvent) => {
    try {
      const event = JSON.parse(e.data);
      onEvent({ ...event, event_type: e.type });
    } catch (err) {
      onError?.(err as Error);
    }
  };

  eventSource.addEventListener('flow', handler as EventListener);
  eventSource.addEventListener('flow_end', handler as EventListener);
  eventSource.onmessage = handler;

  eventSource.onerror = () => {
    onError?.(new Error('Wiretap connection error'));
  };

  return () => eventSource.close();
}

// Service Accounts
export async function getServiceAccounts(): Promise<ServiceAccount[]> {
  return fetchJSON<ServiceAccount[]>('/service-accounts');
}

export async function createServiceAccount(req: CreateServiceAccountRequest): Promise<ServiceAccount> {
  return fetchJSON<ServiceAccount>('/service-accounts', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function revokeServiceAccount(id: string): Promise<void> {
  await fetchJSON<void>(`/service-accounts/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export async function getServiceAccountTokens(id: string): Promise<ServiceAccountToken[]> {
  return fetchJSON<ServiceAccountToken[]>(`/service-accounts/${encodeURIComponent(id)}/tokens`);
}

export async function createServiceAccountToken(
  id: string,
  req: CreateServiceAccountTokenRequest
): Promise<CreateServiceAccountTokenResponse> {
  return fetchJSON<CreateServiceAccountTokenResponse>(`/service-accounts/${encodeURIComponent(id)}/tokens`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function revokeServiceAccountToken(id: string, tokenId: string): Promise<void> {
  await fetchJSON<void>(
    `/service-accounts/${encodeURIComponent(id)}/tokens/${encodeURIComponent(tokenId)}`,
    { method: 'DELETE' }
  );
}
