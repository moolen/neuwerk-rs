import React from 'react';

interface LoginTokenFormProps {
  tokenInput: string;
  tokenLoading: boolean;
  tokenError: string;
  onTokenInputChange: (value: string) => void;
  onSubmit: () => void;
}

export const LoginTokenForm: React.FC<LoginTokenFormProps> = ({
  tokenInput,
  tokenLoading,
  tokenError,
  onTokenInputChange,
  onSubmit,
}) => (
  <form
    onSubmit={(e) => {
      e.preventDefault();
      void onSubmit();
    }}
    className="space-y-4"
  >
    <div>
      <label htmlFor="token" className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Token Login
      </label>
      <input
        id="token"
        type="text"
        value={tokenInput}
        onChange={(e) => onTokenInputChange(e.target.value)}
        disabled={tokenLoading}
        placeholder="Paste token"
        className="w-full px-3 py-2.5 rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        style={{
          background: 'var(--bg-input)',
          border: `1px solid ${tokenError ? 'var(--red-border)' : 'var(--border-subtle)'}`,
          color: 'var(--text)',
        }}
      />
      {tokenError && (
        <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>
          {tokenError}
        </p>
      )}
    </div>

    <button
      type="submit"
      disabled={tokenLoading}
      className="w-full py-2.5 px-4 text-sm font-semibold text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      style={{
        background: 'linear-gradient(135deg, var(--accent), var(--purple))',
      }}
    >
      {tokenLoading ? 'Signing in...' : 'Sign in'}
    </button>
  </form>
);
