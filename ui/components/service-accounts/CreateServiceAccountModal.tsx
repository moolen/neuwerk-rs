import React, { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import type { CreateServiceAccountRequest } from '../../types';

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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName('');
    setDescription('');
    setError(null);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    try {
      setLoading(true);
      await onSubmit({
        name: name.trim(),
        description: description.trim() ? description.trim() : undefined,
      });
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
          <div className="space-y-4 mb-6">
            <div>
              <label htmlFor="name" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={loading}
                placeholder="ci-deployer"
                className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
              />
            </div>

            <div>
              <label htmlFor="description" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Description (optional)
              </label>
              <textarea
                id="description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={loading}
                rows={3}
                placeholder="Used by CI pipeline"
                className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
              />
            </div>

            {error && (
              <div className="p-3 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
                <p className="text-sm" style={{ color: 'var(--red)' }}>{error}</p>
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
              {loading ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
