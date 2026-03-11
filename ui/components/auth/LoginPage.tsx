import React from 'react';
import { Github } from 'lucide-react';
import { buildSsoStartPath } from '../../services/api';
import { LoginTokenForm } from './LoginTokenForm';
import { useSsoProviders } from './useSsoProviders';
import { useTokenLogin } from './useTokenLogin';

export function LoginPage() {
  const { tokenInput, setTokenInput, tokenLoading, tokenError, submit } = useTokenLogin();
  const { providers, loading: ssoLoading, error: ssoError } = useSsoProviders();

  const startSso = (providerId: string) => {
    const nextPath = window.location.pathname === '/login' ? '/' : window.location.pathname;
    window.location.assign(buildSsoStartPath(providerId, nextPath));
  };

  return (
    <div
      className="flex items-center justify-center min-h-screen px-4 py-10"
      style={{ background: 'var(--bg)', position: 'relative', zIndex: 1, overflow: 'hidden' }}
    >
      <div
        aria-hidden
        className="absolute rounded-full"
        style={{
          width: 420,
          height: 420,
          top: -120,
          left: -120,
          background: 'radial-gradient(circle, rgba(79,110,247,0.24) 0%, rgba(79,110,247,0) 70%)',
          pointerEvents: 'none',
        }}
      />
      <div
        aria-hidden
        className="absolute rounded-full"
        style={{
          width: 420,
          height: 420,
          bottom: -180,
          right: -120,
          background: 'radial-gradient(circle, rgba(139,92,246,0.2) 0%, rgba(139,92,246,0) 72%)',
          pointerEvents: 'none',
        }}
      />
      <div
        className="relative p-8 max-w-lg w-full"
        style={{
          background: 'linear-gradient(180deg, var(--bg-glass-strong) 0%, var(--bg-glass) 100%)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid var(--border-glass)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="mb-6">
          <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--accent)' }}>
            Neuwerk Firewall
          </p>
          <h2 className="text-2xl font-semibold" style={{ color: 'var(--text)' }}>Sign in</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            Continue with token login or choose SSO.
          </p>
        </div>

        <div className="space-y-5">
          <LoginTokenForm
            tokenInput={tokenInput}
            tokenLoading={tokenLoading}
            tokenError={tokenError}
            onTokenInputChange={setTokenInput}
            onSubmit={submit}
          />

          <div className="flex items-center gap-3" aria-label="or sign in with SSO">
            <span
              className="h-px flex-1"
              style={{ background: 'linear-gradient(90deg, transparent, var(--border-subtle))' }}
            />
            <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              or
            </span>
            <span
              className="h-px flex-1"
              style={{ background: 'linear-gradient(90deg, var(--border-subtle), transparent)' }}
            />
          </div>

          <div className="space-y-3">
            {ssoLoading && (
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                Loading SSO providers...
              </p>
            )}
            {!ssoLoading && ssoError && (
              <p className="text-sm" style={{ color: 'var(--red)' }}>
                {ssoError}
              </p>
            )}
            {!ssoLoading && !ssoError && providers.length === 0 && (
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                No SSO providers configured.
              </p>
            )}
            {!ssoLoading &&
              !ssoError &&
              providers.map((provider) => (
                <button
                  key={provider.id}
                  type="button"
                  onClick={() => startSso(provider.id)}
                  className="w-full py-2.5 px-4 text-sm font-semibold rounded-lg border transition-colors"
                  style={{
                    background: 'var(--bg-input)',
                    borderColor: 'var(--border-subtle)',
                    color: 'var(--text)',
                  }}
                >
                  <span className="inline-flex items-center justify-center gap-2">
                    {provider.kind === 'google' && (
                      <span
                        aria-hidden
                        className="inline-flex h-5 w-5 items-center justify-center rounded-full text-xs font-bold"
                        style={{
                          background: 'linear-gradient(135deg, #34a853, #4285f4)',
                          color: 'white',
                        }}
                      >
                        G
                      </span>
                    )}
                    {provider.kind === 'github' && <Github className="w-4 h-4" />}
                    {provider.kind === 'generic-oidc' && (
                      <span
                        aria-hidden
                        className="inline-flex h-5 w-5 items-center justify-center rounded-full text-xs font-bold"
                        style={{
                          background: 'var(--accent)',
                          color: 'white',
                        }}
                      >
                        O
                      </span>
                    )}
                    {`Continue with ${provider.name}`}
                  </span>
                </button>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
}
