import React, { useState, useEffect } from 'react';
import { Plus } from 'lucide-react';
import { ServiceAccountTable } from '../components/service-accounts/ServiceAccountTable';
import { CreateServiceAccountModal } from '../components/service-accounts/CreateServiceAccountModal';
import { TokenRevealDialog } from '../components/service-accounts/TokenRevealDialog';
import {
  getServiceAccounts,
  createServiceAccount,
  revokeServiceAccount,
  getServiceAccountTokens,
  createServiceAccountToken,
  revokeServiceAccountToken,
} from '../services/api';
import type {
  ServiceAccount,
  ServiceAccountToken,
  CreateServiceAccountRequest,
  CreateServiceAccountTokenRequest,
} from '../types';

export const ServiceAccountsPage: React.FC = () => {
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showTokenDialog, setShowTokenDialog] = useState(false);
  const [createdToken, setCreatedToken] = useState<{ token: string; name?: string } | null>(null);

  const [selectedAccount, setSelectedAccount] = useState<ServiceAccount | null>(null);
  const [tokens, setTokens] = useState<ServiceAccountToken[]>([]);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [showTokenModal, setShowTokenModal] = useState(false);

  useEffect(() => {
    loadServiceAccounts();
  }, []);

  const loadServiceAccounts = async () => {
    try {
      setLoading(true);
      setError(null);
      const accounts = await getServiceAccounts();
      setServiceAccounts(accounts || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load service accounts');
    } finally {
      setLoading(false);
    }
  };

  const loadTokens = async (account: ServiceAccount) => {
    try {
      setTokenLoading(true);
      setTokenError(null);
      const list = await getServiceAccountTokens(account.id);
      setTokens(list || []);
      setSelectedAccount(account);
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to load tokens');
    } finally {
      setTokenLoading(false);
    }
  };

  const handleCreateSubmit = async (req: CreateServiceAccountRequest) => {
    try {
      await createServiceAccount(req);
      setShowCreateModal(false);
      await loadServiceAccounts();
    } catch (err) {
      throw err;
    }
  };

  const handleDisableAccount = async (id: string) => {
    const confirm = window.confirm('Disable this service account and revoke all tokens?');
    if (!confirm) return;
    try {
      await revokeServiceAccount(id);
      await loadServiceAccounts();
      if (selectedAccount?.id === id) {
        setSelectedAccount(null);
        setTokens([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disable service account');
    }
  };

  const handleCreateToken = async (req: CreateServiceAccountTokenRequest) => {
    if (!selectedAccount) return;
    try {
      const response = await createServiceAccountToken(selectedAccount.id, req);
      setCreatedToken({ token: response.token, name: response.token_meta.name || undefined });
      setShowTokenDialog(true);
      setShowTokenModal(false);
      await loadTokens(selectedAccount);
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to create token');
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    if (!selectedAccount) return;
    const confirm = window.confirm('Revoke this token?');
    if (!confirm) return;
    try {
      await revokeServiceAccountToken(selectedAccount.id, tokenId);
      await loadTokens(selectedAccount);
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to revoke token');
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold mb-1" style={{ color: 'var(--text)' }}>Service Accounts</h1>
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
        <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
          <p className="text-sm" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      )}

      {loading ? (
        <div className="rounded-xl p-12 text-center" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <p style={{ color: 'var(--text-muted)' }}>Loading service accounts...</p>
        </div>
      ) : (
        <ServiceAccountTable
          serviceAccounts={serviceAccounts}
          onDisable={handleDisableAccount}
          onSelectTokens={loadTokens}
        />
      )}

      {selectedAccount && (
        <div className="mt-6 rounded-xl p-6" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>Tokens for {selectedAccount.name}</h2>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{selectedAccount.id}</p>
            </div>
            <button
              onClick={() => setShowTokenModal(true)}
              className="px-3 py-2 text-sm rounded-lg text-white"
              style={{ background: 'var(--accent)' }}
            >
              Create Token
            </button>
          </div>

          {tokenError && (
            <div className="mt-4 p-3 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
              <p className="text-sm" style={{ color: 'var(--red)' }}>{tokenError}</p>
            </div>
          )}

          {tokenLoading ? (
            <div className="mt-4 text-sm" style={{ color: 'var(--text-muted)' }}>Loading tokens...</div>
          ) : tokens.length === 0 ? (
            <div className="mt-4 text-sm" style={{ color: 'var(--text-muted)' }}>No tokens yet.</div>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
                    <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Name</th>
                    <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Status</th>
                    <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Created</th>
                    <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Expires</th>
                    <th className="text-left py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Last Used</th>
                    <th className="text-right py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token) => (
                    <tr key={token.id} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
                      <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>{token.name || '-'}</td>
                      <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-secondary)' }}>{token.status}</td>
                      <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(token.created_at)}</td>
                      <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(token.expires_at)}</td>
                      <td className="py-2 px-2 text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(token.last_used_at)}</td>
                      <td className="py-2 px-2 text-right">
                        <button
                          onClick={() => handleRevokeToken(token.id)}
                          className="px-2 py-1 text-xs rounded-lg"
                          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
                          disabled={token.status === 'revoked'}
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {showCreateModal && (
        <CreateServiceAccountModal
          onSubmit={handleCreateSubmit}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {showTokenModal && selectedAccount && (
        <CreateTokenModal
          onClose={() => setShowTokenModal(false)}
          onSubmit={handleCreateToken}
        />
      )}

      {showTokenDialog && createdToken && (
        <TokenRevealDialog
          token={createdToken.token}
          name={createdToken.name}
          onClose={() => {
            setShowTokenDialog(false);
            setCreatedToken(null);
          }}
        />
      )}
    </div>
  );
};

const formatTimestamp = (value?: string | null): string => {
  if (!value) return 'N/A';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return 'N/A';
  }
};

const CreateTokenModal = ({ onClose, onSubmit }: { onClose: () => void; onSubmit: (req: CreateServiceAccountTokenRequest) => void; }) => {
  const [name, setName] = useState('');
  const [ttl, setTtl] = useState('');
  const [eternal, setEternal] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: name.trim() ? name.trim() : undefined,
      ttl: ttl.trim() ? ttl.trim() : undefined,
      eternal,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div className="relative rounded-xl border p-6 max-w-md w-full shadow-xl my-auto" style={{ background: 'var(--bg-glass-strong)', borderColor: 'var(--border-glass)' }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>Create Token</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Name (optional)</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 rounded-lg text-sm"
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
              placeholder="prod-reader"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>TTL (optional)</label>
            <input
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              className="w-full px-3 py-2 rounded-lg text-sm"
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
              placeholder="90d or 24h"
              disabled={eternal}
            />
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>If empty, default TTL applies.</p>
          </div>
          <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
            <input type="checkbox" checked={eternal} onChange={() => setEternal(!eternal)} />
            Eternal (no expiry)
          </label>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm rounded-lg"
              style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 text-sm rounded-lg text-white"
              style={{ background: 'var(--accent)' }}
            >
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
