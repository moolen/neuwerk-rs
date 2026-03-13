import React, { useEffect, useState } from 'react';
import { X } from 'lucide-react';

import type { ServiceAccount, ServiceAccountRole, UpdateServiceAccountRequest } from '../../types';
import { CreateServiceAccountModalFields } from './CreateServiceAccountModalFields';
import { buildUpdateServiceAccountRequest } from './createForm';

interface EditServiceAccountModalProps {
  account: ServiceAccount;
  onSubmit: (req: UpdateServiceAccountRequest) => Promise<void>;
  onClose: () => void;
}

export const EditServiceAccountModal: React.FC<EditServiceAccountModalProps> = ({
  account,
  onSubmit,
  onClose,
}) => {
  const [name, setName] = useState(account.name);
  const [description, setDescription] = useState(account.description ?? '');
  const [role, setRole] = useState<ServiceAccountRole>(account.role);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName(account.name);
    setDescription(account.description ?? '');
    setRole(account.role);
    setError(null);
  }, [account]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const result = buildUpdateServiceAccountRequest(name, description, role);
    if (!result.request) {
      setError(result.error ?? 'Invalid request');
      return;
    }

    try {
      setLoading(true);
      await onSubmit(result.request);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update service account');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50" onClick={loading ? undefined : onClose} />
      <div
        className="relative rounded-xl border p-6 max-w-md w-full shadow-xl my-auto"
        style={{ background: 'var(--bg-glass-strong)', borderColor: 'var(--border-glass)' }}
      >
        <button
          onClick={onClose}
          disabled={loading}
          className="absolute top-4 right-4 text-slate-400 hover:text-white disabled:opacity-50"
        >
          <X className="w-5 h-5" />
        </button>

        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>
          Edit Service Account
        </h3>

        <form onSubmit={handleSubmit}>
          <CreateServiceAccountModalFields
            name={name}
            description={description}
            role={role}
            loading={loading}
            onNameChange={setName}
            onDescriptionChange={setDescription}
            onRoleChange={setRole}
          />

          <div className="mb-6">
            {error && (
              <div
                className="p-3 rounded-lg"
                style={{
                  background: 'var(--red-bg)',
                  border: '1px solid var(--red-border)',
                }}
              >
                <p className="text-sm" style={{ color: 'var(--red)' }}>
                  {error}
                </p>
              </div>
            )}
          </div>

          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ background: 'var(--accent)' }}
            >
              {loading ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
