import type { CreateServiceAccountTokenRequest, ServiceAccountRole } from '../../../types';

export const TOKEN_TTL_PRESETS = ['24h', '7d', '30d', '90d'] as const;

export function buildCreateTokenRequest(
  nameInput: string,
  ttlInput: string,
  eternal: boolean,
  role: ServiceAccountRole
): CreateServiceAccountTokenRequest {
  return {
    name: nameInput.trim() ? nameInput.trim() : undefined,
    ttl: ttlInput.trim() ? ttlInput.trim() : undefined,
    eternal,
    role,
  };
}
