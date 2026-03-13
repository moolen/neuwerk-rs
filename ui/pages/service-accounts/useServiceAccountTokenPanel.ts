import { useState } from 'react';
import type {
  CreateServiceAccountTokenRequest,
  ServiceAccount,
  ServiceAccountToken,
  ServiceAccountRole,
} from '../../types';
import { toUiError } from './helpers';
import {
  createServiceAccountTokenRemote,
  loadServiceAccountTokensRemote,
  revokeServiceAccountTokenRemote,
} from './remote';

export function useServiceAccountTokenPanel() {
  const [showTokenDialog, setShowTokenDialog] = useState(false);
  const [createdToken, setCreatedToken] = useState<{
    token: string;
    name?: string;
    role?: ServiceAccountRole;
  } | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<ServiceAccount | null>(null);
  const [tokens, setTokens] = useState<ServiceAccountToken[]>([]);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [showTokenModal, setShowTokenModal] = useState(false);

  const loadTokens = async (account: ServiceAccount) => {
    try {
      setTokenLoading(true);
      setTokenError(null);
      const list = await loadServiceAccountTokensRemote(account.id);
      setTokens(list);
      setSelectedAccount(account);
    } catch (err) {
      setTokenError(toUiError(err, 'Failed to load tokens'));
    } finally {
      setTokenLoading(false);
    }
  };

  const handleCreateToken = async (req: CreateServiceAccountTokenRequest) => {
    if (!selectedAccount) return;
    try {
      const response = await createServiceAccountTokenRemote(selectedAccount.id, req);
      setCreatedToken({
        token: response.token,
        name: response.token_meta.name || undefined,
        role: response.token_meta.role,
      });
      setShowTokenDialog(true);
      setShowTokenModal(false);
      await loadTokens(selectedAccount);
    } catch (err) {
      setTokenError(toUiError(err, 'Failed to create token'));
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    if (!selectedAccount) return;
    const confirmed = window.confirm('Revoke this token?');
    if (!confirmed) return;
    try {
      await revokeServiceAccountTokenRemote(selectedAccount.id, tokenId);
      await loadTokens(selectedAccount);
    } catch (err) {
      setTokenError(toUiError(err, 'Failed to revoke token'));
    }
  };

  const closeTokenDialog = () => {
    setShowTokenDialog(false);
    setCreatedToken(null);
  };

  const clearSelection = () => {
    setSelectedAccount(null);
    setTokens([]);
  };

  const syncSelectedAccount = (account: ServiceAccount | null) => {
    setSelectedAccount(account);
  };

  return {
    showTokenDialog,
    createdToken,
    selectedAccount,
    tokens,
    tokenLoading,
    tokenError,
    showTokenModal,
    setShowTokenModal,
    loadTokens,
    handleCreateToken,
    handleRevokeToken,
    closeTokenDialog,
    clearSelection,
    syncSelectedAccount,
  };
}
