import React, { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import type { CreateServiceAccountRequest, ServiceAccountRole } from '../../types';
import { CreateServiceAccountModalActions } from './CreateServiceAccountModalActions';
import { CreateServiceAccountModalFields } from './CreateServiceAccountModalFields';
import { buildCreateServiceAccountRequest } from './createForm';

interface CreateServiceAccountModalProps {
  onSubmit: (req: CreateServiceAccountRequest) => Promise<void>;
  onClose: () => void;
}

export const CreateServiceAccountModal: React.FC<CreateServiceAccountModalProps> = ({
  onSubmit,
  onClose,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [role, setRole] = useState<ServiceAccountRole>('readonly');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName('');
    setDescription('');
    setRole('readonly');
    setError(null);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const result = buildCreateServiceAccountRequest(name, description, role);
    if (!result.request) {
      setError(result.error ?? 'Invalid request');
      return;
    }

    try {
      setLoading(true);
      await onSubmit(result.request);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create service account');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50" onClick={loading ? undefined : onClose} />
      <div className="relative rounded-xl border p-6 max-w-md w-full shadow-xl my-auto" style={{ background: 'var(--bg-glass-strong)', borderColor: 'var(--border-glass)' }}>
        <button
          onClick={onClose}
          disabled={loading}
          className="absolute top-4 right-4 text-slate-400 hover:text-white disabled:opacity-50"
        >
          <X className="w-5 h-5" />
        </button>

        <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text)' }}>Create Service Account</h3>

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
              <div className="p-3 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
                <p className="text-sm" style={{ color: 'var(--red)' }}>{error}</p>
              </div>
            )}
          </div>

          <CreateServiceAccountModalActions loading={loading} onClose={onClose} />
        </form>
      </div>
    </div>
  );
};
