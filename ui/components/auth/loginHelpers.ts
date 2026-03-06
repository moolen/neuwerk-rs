import type { AuthUser } from '../../types';

const LOCAL_PREVIEW_AUTH_KEY = 'neuwerk.local_preview_auth_user';

export function validateLoginTokenInput(tokenInput: string): { token?: string; error?: string } {
  const trimmedToken = tokenInput.trim().replace(/^bearer\s+/i, '');
  if (!trimmedToken) {
    return { error: 'Token is required' };
  }
  return { token: trimmedToken };
}

export function toLoginErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return 'Invalid token. Please check and try again.';
}

export function isLocalPreviewAuthBypassEnabled(hostname?: string): boolean {
  const effectiveHostname =
    hostname ?? (typeof window !== 'undefined' ? window.location.hostname : '');
  return (
    effectiveHostname === 'localhost' ||
    effectiveHostname === '127.0.0.1' ||
    effectiveHostname === '::1'
  );
}

export function createLocalPreviewAuthUser(): AuthUser {
  return {
    sub: 'local-preview-admin',
    roles: ['admin'],
  };
}

export function readLocalPreviewAuthUser(
  storage?: Pick<Storage, 'getItem' | 'removeItem'>,
  hostname?: string
): AuthUser | null {
  if (!isLocalPreviewAuthBypassEnabled(hostname)) {
    return null;
  }

  const localStorageRef = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!localStorageRef) {
    return null;
  }

  const raw = localStorageRef.getItem(LOCAL_PREVIEW_AUTH_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<AuthUser>;
    if (typeof parsed.sub !== 'string' || !Array.isArray(parsed.roles)) {
      throw new Error('Invalid shape');
    }
    return {
      sub: parsed.sub,
      roles: parsed.roles.filter((value): value is string => typeof value === 'string'),
      sa_id: parsed.sa_id ?? null,
      exp: parsed.exp ?? null,
    };
  } catch {
    localStorageRef.removeItem(LOCAL_PREVIEW_AUTH_KEY);
    return null;
  }
}

export function writeLocalPreviewAuthUser(
  user: AuthUser = createLocalPreviewAuthUser(),
  storage?: Pick<Storage, 'setItem'>,
  hostname?: string
): void {
  if (!isLocalPreviewAuthBypassEnabled(hostname)) {
    return;
  }

  const localStorageRef = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!localStorageRef) {
    return;
  }

  localStorageRef.setItem(LOCAL_PREVIEW_AUTH_KEY, JSON.stringify(user));
}

export function clearLocalPreviewAuthUser(
  storage?: Pick<Storage, 'removeItem'>,
  hostname?: string
): void {
  if (!isLocalPreviewAuthBypassEnabled(hostname)) {
    return;
  }

  const localStorageRef = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!localStorageRef) {
    return;
  }

  localStorageRef.removeItem(LOCAL_PREVIEW_AUTH_KEY);
}
