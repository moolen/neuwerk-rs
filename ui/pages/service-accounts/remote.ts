import {
  createServiceAccount,
  createServiceAccountToken,
  getServiceAccountTokens,
  getServiceAccounts,
  revokeServiceAccount,
  revokeServiceAccountToken,
  updateServiceAccount,
} from '../../services/api';
import type {
  CreateServiceAccountRequest,
  CreateServiceAccountTokenRequest,
  ServiceAccountToken,
  UpdateServiceAccountRequest,
} from '../../types';

export async function loadServiceAccountsRemote() {
  const accounts = await getServiceAccounts();
  return accounts || [];
}

export async function loadServiceAccountTokensRemote(accountId: string): Promise<ServiceAccountToken[]> {
  const list = await getServiceAccountTokens(accountId);
  return list || [];
}

export async function createServiceAccountRemote(req: CreateServiceAccountRequest): Promise<void> {
  await createServiceAccount(req);
}

export async function updateServiceAccountRemote(
  accountId: string,
  req: UpdateServiceAccountRequest
): Promise<void> {
  await updateServiceAccount(accountId, req);
}

export async function disableServiceAccountRemote(accountId: string): Promise<void> {
  await revokeServiceAccount(accountId);
}

export async function createServiceAccountTokenRemote(
  accountId: string,
  req: CreateServiceAccountTokenRequest
) {
  return createServiceAccountToken(accountId, req);
}

export async function revokeServiceAccountTokenRemote(accountId: string, tokenId: string): Promise<void> {
  await revokeServiceAccountToken(accountId, tokenId);
}
