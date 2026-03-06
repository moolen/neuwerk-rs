import React from 'react';

interface CreateTokenModalActionsProps {
  onClose: () => void;
}

export const CreateTokenModalActions: React.FC<CreateTokenModalActionsProps> = ({ onClose }) => (
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
);
