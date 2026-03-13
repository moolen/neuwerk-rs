import React, { useState } from 'react';
import type { ServiceAccountRole } from '../../types';
import { serviceAccountRoleLabel } from './helpers';

interface TokenRevealDialogProps {
  token: string;
  name?: string;
  role?: ServiceAccountRole;
  onClose: () => void;
}

export const TokenRevealDialog: React.FC<TokenRevealDialogProps> = ({
  token,
  name,
  role,
  onClose,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy token:', err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50" />
      <div className="relative rounded-xl border p-6 max-w-lg w-full shadow-xl my-auto" style={{ background: 'var(--bg-glass-strong)', borderColor: 'var(--border-glass)' }}>
        <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--green)' }}>Token Minted</h3>
        <p className="mb-4" style={{ color: 'var(--text-secondary)' }}>
          {name ? `Token '${name}' created successfully.` : 'Token created successfully.'}
        </p>
        {role && (
          <p className="mb-4 text-sm" style={{ color: 'var(--text-muted)' }}>
            This token carries the <strong>{serviceAccountRoleLabel(role)}</strong> role and the
            value is only shown once.
          </p>
        )}

        <div className="mb-4">
          <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Token</label>
          <div className="rounded-lg p-3 overflow-hidden" style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)' }}>
            <code className="text-sm font-mono block truncate" style={{ color: 'var(--text-secondary)' }}>{token}</code>
          </div>
          <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
            Copy this token now. It will not be shown again.
          </p>
        </div>

        <div className="flex flex-col space-y-2">
          <button
            onClick={handleCopy}
            className="w-full px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors"
            style={{ background: 'var(--accent)' }}
          >
            {copied ? 'Copied!' : 'Copy Token'}
          </button>
          <button
            onClick={onClose}
            className="w-full px-4 py-2 text-sm font-medium rounded-lg transition-colors"
            style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
