import React from 'react';

interface CreateServiceAccountModalActionsProps {
  loading: boolean;
  onClose: () => void;
}

export const CreateServiceAccountModalActions: React.FC<CreateServiceAccountModalActionsProps> = ({
  loading,
  onClose,
}) => (
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
);
