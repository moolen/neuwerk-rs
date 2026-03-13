import type {
  CreateServiceAccountRequest,
  ServiceAccountRole,
  UpdateServiceAccountRequest,
} from '../../types';

function normalizeServiceAccountRequest(
  name: string,
  description: string,
  role: ServiceAccountRole
): { name: string; description?: string; role: ServiceAccountRole } {
  const trimmedDescription = description.trim();
  return {
    name: name.trim(),
    description: trimmedDescription ? trimmedDescription : undefined,
    role,
  };
}

export function buildCreateServiceAccountRequest(
  name: string,
  description: string,
  role: ServiceAccountRole
): { request?: CreateServiceAccountRequest; error?: string } {
  const trimmedName = name.trim();
  if (!trimmedName) {
    return { error: 'Name is required' };
  }

  return {
    request: normalizeServiceAccountRequest(name, description, role),
  };
}

export function buildUpdateServiceAccountRequest(
  name: string,
  description: string,
  role: ServiceAccountRole
): { request?: UpdateServiceAccountRequest; error?: string } {
  const trimmedName = name.trim();
  if (!trimmedName) {
    return { error: 'Name is required' };
  }

  return {
    request: normalizeServiceAccountRequest(name, description, role),
  };
}
