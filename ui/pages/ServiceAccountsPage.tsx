import React from 'react';
import { Plus } from 'lucide-react';
import { CreateServiceAccountModal } from '../components/service-accounts/CreateServiceAccountModal';
import { EditServiceAccountModal } from '../components/service-accounts/EditServiceAccountModal';
import { ServiceAccountTable } from '../components/service-accounts/ServiceAccountTable';
import { TokenRevealDialog } from '../components/service-accounts/TokenRevealDialog';
import { CreateTokenModal } from './service-accounts/components/CreateTokenModal';
import { ServiceAccountTokensPanel } from './service-accounts/components/ServiceAccountTokensPanel';
import { useServiceAccountsPage } from './service-accounts/useServiceAccountsPage';

export const ServiceAccountsPage: React.FC = () => {
  const {
    serviceAccounts,
    loading,
    error,
    showCreateModal,
    setShowCreateModal,
    showEditModal,
    editingAccount,
    showTokenDialog,
    createdToken,
    closeTokenDialog,
    selectedAccount,
    tokens,
    tokenLoading,
    tokenError,
    showTokenModal,
    setShowTokenModal,
    loadTokens,
    handleCreateSubmit,
    handleEditSubmit,
    handleDisableAccount,
    handleOpenEditModal,
    handleCloseEditModal,
    handleCreateToken,
    handleRevokeToken,
  } = useServiceAccountsPage();

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold mb-1" style={{ color: 'var(--text)' }}>
            Service Accounts
          </h1>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            Create service accounts and mint JWTs for API access.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 text-white rounded-lg flex items-center space-x-2 transition-colors"
          style={{ background: 'var(--accent)' }}
        >
          <Plus className="w-4 h-4" />
          <span>Create Service Account</span>
        </button>
      </div>

      {error && (
        <div
          className="mb-4 p-4 rounded-lg"
          style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}
        >
          <p className="text-sm" style={{ color: 'var(--red)' }}>
            {error}
          </p>
        </div>
      )}

      {loading ? (
        <div
          className="rounded-xl p-12 text-center"
          style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
        >
          <p style={{ color: 'var(--text-muted)' }}>Loading service accounts...</p>
        </div>
      ) : (
        <ServiceAccountTable
          serviceAccounts={serviceAccounts}
          onDisable={handleDisableAccount}
          onEdit={handleOpenEditModal}
          onSelectTokens={(account) => void loadTokens(account)}
        />
      )}

      {selectedAccount && (
        <ServiceAccountTokensPanel
          account={selectedAccount}
          tokenLoading={tokenLoading}
          tokenError={tokenError}
          tokens={tokens}
          onCreateToken={() => setShowTokenModal(true)}
          onRevokeToken={(tokenId) => void handleRevokeToken(tokenId)}
        />
      )}

      {showCreateModal && (
        <CreateServiceAccountModal
          onSubmit={handleCreateSubmit}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {showTokenModal && selectedAccount && (
        <CreateTokenModal
          accountRole={selectedAccount.role}
          onClose={() => setShowTokenModal(false)}
          onSubmit={(req) => void handleCreateToken(req)}
        />
      )}

      {showEditModal && editingAccount && (
        <EditServiceAccountModal
          account={editingAccount}
          onSubmit={handleEditSubmit}
          onClose={handleCloseEditModal}
        />
      )}

      {showTokenDialog && createdToken && (
        <TokenRevealDialog
          token={createdToken.token}
          name={createdToken.name}
          role={createdToken.role}
          onClose={closeTokenDialog}
        />
      )}
    </div>
  );
};
