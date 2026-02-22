import React, { useState } from 'react';
import { loginWithToken } from '../../services/api';

export function LoginPage() {
  const [tokenInput, setTokenInput] = useState('');
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenError, setTokenError] = useState('');

  const handleTokenLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setTokenError('');

    const trimmedToken = tokenInput.trim();
    if (!trimmedToken) {
      setTokenError('Token is required');
      return;
    }

    setTokenLoading(true);
    try {
      await loginWithToken(trimmedToken);
      window.location.href = '/';
    } catch (err) {
      if (err instanceof Error) {
        setTokenError(err.message);
      } else {
        setTokenError('Invalid token. Please check and try again.');
      }
    } finally {
      setTokenLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: 'var(--bg)', position: 'relative', zIndex: 1 }}>
      <div
        className="p-8 max-w-md w-full mx-4"
        style={{
          background: 'var(--bg-glass-strong)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid var(--border-glass)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <h2 className="text-2xl font-semibold mb-4 text-center" style={{ color: 'var(--text)' }}>Sign In</h2>

        <p className="text-sm mb-6" style={{ color: 'var(--text-muted)' }}>
          Paste a JWT minted with the CLI. Example:
          <span className="block mt-2 font-mono text-xs" style={{ color: 'var(--text)' }}>
            firewall auth token mint --sub &lt;id&gt; --cluster-addr &lt;ip:port&gt;
          </span>
        </p>

        <form onSubmit={handleTokenLogin} className="space-y-4">
          <div>
            <label htmlFor="token" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              JWT Token
            </label>
            <input
              id="token"
              type="text"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              disabled={tokenLoading}
              placeholder="ey..."
              className="w-full px-3 py-2 rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text)',
              }}
            />
            {tokenError && (
              <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>{tokenError}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={tokenLoading}
            className="w-full py-2.5 px-4 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ background: 'var(--accent)' }}
          >
            {tokenLoading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
