import { useEffect, useState } from 'react';
import type {
  CreateServiceAccountRequest,
  ServiceAccount,
} from '../../types';
import { toUiError } from './helpers';
import {
  createServiceAccountRemote,
  disableServiceAccountRemote,
  loadServiceAccountsRemote,
} from './remote';
import { useServiceAccountTokenPanel } from './useServiceAccountTokenPanel';

export function useServiceAccountsPage() {
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const tokenPanel = useServiceAccountTokenPanel();

  useEffect(() => {
    void loadServiceAccounts();
  }, []);

  const loadServiceAccounts = async () => {
    try {
      setLoading(true);
      setError(null);
      const accounts = await loadServiceAccountsRemote();
      setServiceAccounts(accounts);
    } catch (err) {
      setError(toUiError(err, 'Failed to load service accounts'));
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSubmit = async (req: CreateServiceAccountRequest) => {
    await createServiceAccountRemote(req);
    setShowCreateModal(false);
    await loadServiceAccounts();
  };

  const handleDisableAccount = async (id: string) => {
    const confirmed = window.confirm('Disable this service account and revoke all tokens?');
    if (!confirmed) return;
    try {
      await disableServiceAccountRemote(id);
      await loadServiceAccounts();
      if (tokenPanel.selectedAccount?.id === id) {
        tokenPanel.clearSelection();
      }
    } catch (err) {
      setError(toUiError(err, 'Failed to disable service account'));
    }
  };

  return {
    serviceAccounts,
    loading,
    error,
    showCreateModal,
    setShowCreateModal,
    handleCreateSubmit,
    handleDisableAccount,
    ...tokenPanel,
  };
}
