import React from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  confirmVariant?: 'danger' | 'warning' | 'primary';
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmVariant = 'primary',
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  const confirmStyles: Record<string, React.CSSProperties> = {
    danger: { background: 'var(--red)', color: 'white' },
    warning: { background: 'var(--amber)', color: 'white' },
    primary: { background: 'var(--accent)', color: 'white' },
  };

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onCancel} />
      <div
        className="relative p-6 max-w-md w-full mx-4"
        style={{
          background: 'var(--bg-glass-strong)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid var(--border-glass)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <button
          onClick={onCancel}
          className="absolute top-4 right-4 transition-colors"
          style={{ color: 'var(--text-muted)' }}
        >
          <X className="w-5 h-5" />
        </button>
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--text)' }}>{title}</h3>
        <p className="mb-6" style={{ color: 'var(--text-secondary)' }}>{message}</p>
        <div className="flex justify-end space-x-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            style={{
              color: 'var(--text-secondary)',
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            style={confirmStyles[confirmVariant]}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
};
