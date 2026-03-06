const API_BASE = '/api/v1';

export class APIError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'APIError';
  }
}

export function clearAuthToken() {
  // Auth is cookie-backed; no client-side token cache is maintained.
}

function extractApiErrorMessage(body: unknown, fallback: string): string {
  if (typeof body === 'string' && body.trim().length > 0) {
    return body;
  }
  if (body && typeof body === 'object') {
    const record = body as Record<string, unknown>;
    const error = record.error;
    if (typeof error === 'string' && error.trim().length > 0) {
      return error;
    }
    const message = record.message;
    if (typeof message === 'string' && message.trim().length > 0) {
      return message;
    }
  }
  return fallback;
}

export async function fetchJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: options?.credentials ?? 'same-origin',
    headers,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new APIError(res.status, extractApiErrorMessage(body, res.statusText));
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export async function fetchText(path: string, options?: RequestInit): Promise<string> {
  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string>),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: options?.credentials ?? 'same-origin',
    headers,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => res.statusText);
    throw new APIError(res.status, body || res.statusText);
  }

  return res.text();
}

export { API_BASE, extractApiErrorMessage };
