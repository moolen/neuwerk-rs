export const METHOD_SUGGESTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
export const HEADER_SUGGESTIONS = ['Host', 'Authorization', 'Content-Type', 'Accept', 'User-Agent', 'X-Request-ID'];
export const FILE_TYPE_OPTIONS = ['exe', 'msi', 'archive', 'zip', 'tar', 'gz', 'script', 'sh', 'ps1', 'js'];

export function validateRegex(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  try {
    new RegExp(trimmed);
    return null;
  } catch {
    return 'Invalid regular expression';
  }
}

export function validatePort(port: number): string | null {
  if (!Number.isInteger(port)) {
    return 'Port must be an integer';
  }
  if (port < 1 || port > 65535) {
    return 'Port must be between 1 and 65535';
  }
  return null;
}

export function validatePorts(value: string): { ports: number[]; error: string | null } {
  const raw = value.split(',').map((x) => x.trim()).filter(Boolean);
  if (raw.length === 0) {
    return { ports: [], error: 'At least one port is required' };
  }
  const ports: number[] = [];
  for (const item of raw) {
    const n = Number(item);
    if (!Number.isFinite(n)) {
      return { ports: [], error: `Invalid port value: ${item}` };
    }
    const err = validatePort(n);
    if (err) {
      return { ports: [], error: err };
    }
    ports.push(n);
  }
  return { ports, error: null };
}

export function validateMethod(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return 'HTTP method must not be empty';
  }
  if (!/^[A-Z]+$/.test(trimmed)) {
    return 'HTTP methods must be uppercase letters';
  }
  return null;
}
