import { useEffect, useState } from 'react';
import type {
  CreateServiceAccountRequest,
  ServiceAccount,
  UpdateServiceAccountRequest,
} from '../../types';
import { isServiceAccountRoleDowngrade } from '../../components/service-accounts/helpers';
import { toUiError } from './helpers';
import {
  createServiceAccountRemote,
  disableServiceAccountRemote,
  loadServiceAccountsRemote,
  updateServiceAccountRemote,
} from './remote';
import { useServiceAccountTokenPanel } from './useServiceAccountTokenPanel';

export function useServiceAccountsPage() {
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingAccount, setEditingAccount] = useState<ServiceAccount | null>(null);
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
      if (tokenPanel.selectedAccount) {
        const refreshed = accounts.find((account) => account.id === tokenPanel.selectedAccount?.id);
        if (refreshed) {
          tokenPanel.syncSelectedAccount(refreshed);
        } else {
          tokenPanel.clearSelection();
        }
      }
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

  const handleEditSubmit = async (req: UpdateServiceAccountRequest) => {
    if (!editingAccount) return;
    if (isServiceAccountRoleDowngrade(editingAccount.role, req.role)) {
      const confirmed = window.confirm(
        'Downgrading this account to readonly will cause broader existing tokens to stop working for admin-only API calls. Continue?'
      );
      if (!confirmed) return;
    }
    await updateServiceAccountRemote(editingAccount.id, req);
    setShowEditModal(false);
    setEditingAccount(null);
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

  const handleOpenEditModal = (account: ServiceAccount) => {
    setEditingAccount(account);
    setShowEditModal(true);
  };

  const handleCloseEditModal = () => {
    setShowEditModal(false);
    setEditingAccount(null);
  };

  return {
    serviceAccounts,
    loading,
    error,
    showCreateModal,
    setShowCreateModal,
    showEditModal,
    editingAccount,
    handleCreateSubmit,
    handleEditSubmit,
    handleDisableAccount,
    handleOpenEditModal,
    handleCloseEditModal,
    ...tokenPanel,
  };
}
