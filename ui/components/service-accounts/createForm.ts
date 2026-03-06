import type { CreateServiceAccountRequest } from '../../types';

export function buildCreateServiceAccountRequest(
  name: string,
  description: string
): { request?: CreateServiceAccountRequest; error?: string } {
  const trimmedName = name.trim();
  if (!trimmedName) {
    return { error: 'Name is required' };
  }

  const trimmedDescription = description.trim();
  return {
    request: {
      name: trimmedName,
      description: trimmedDescription ? trimmedDescription : undefined,
    },
  };
}
