import React, { useEffect, useState } from 'react';
import {
  getTlsInterceptCaStatus,
  updateTlsInterceptCa,
} from '../services/api';
import type { TlsInterceptCaStatus } from '../types';

export const SettingsPage: React.FC = () => {
  const [status, setStatus] = useState<TlsInterceptCaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');

  useEffect(() => {
    void refresh();
  }, []);

  const refresh = async () => {
    try {
      setLoading(true);
      setError(null);
      const current = await getTlsInterceptCaStatus();
      setStatus(current);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setSuccess(null);
    if (!certPem.trim() || !keyPem.trim()) {
      setError('Certificate PEM and key PEM are required');
      return;
    }
    try {
      setSaving(true);
      const next = await updateTlsInterceptCa(certPem, keyPem);
      setStatus(next);
      setSuccess('TLS intercept CA updated');
      setKeyPem('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update TLS intercept CA');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-1" style={{ color: 'var(--text)' }}>Settings</h1>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Manage TLS interception CA material.
        </p>
      </div>

      {error && (
        <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}>
          <p className="text-sm" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      )}

      {success && (
        <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--green-bg, rgba(34,197,94,0.08))', border: '1px solid var(--green-border, rgba(34,197,94,0.25))' }}>
          <p className="text-sm" style={{ color: 'var(--green, #16a34a)' }}>{success}</p>
        </div>
      )}

      <div className="rounded-xl p-6 mb-6" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>TLS Intercept CA Status</h2>
          <button
            onClick={() => void refresh()}
            className="px-3 py-2 text-sm rounded-lg"
            style={{ background: 'var(--bg-card)', color: 'var(--text)' }}
            disabled={loading}
          >
            Refresh
          </button>
        </div>
        {loading ? (
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading…</p>
        ) : (
          <div className="text-sm space-y-1" style={{ color: 'var(--text-secondary)' }}>
            <p>Configured: <strong>{status?.configured ? 'yes' : 'no'}</strong></p>
            <p>Source: <strong>{status?.source || '-'}</strong></p>
            <p>Fingerprint: <code>{status?.fingerprint_sha256 || '-'}</code></p>
          </div>
        )}
      </div>

      <form onSubmit={onSubmit} className="rounded-xl p-6" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--text)' }}>Update TLS Intercept CA</h2>
        <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>CA Certificate PEM</label>
        <textarea
          className="w-full mb-4 p-3 rounded-lg text-sm font-mono"
          rows={8}
          value={certPem}
          onChange={(e) => setCertPem(e.target.value)}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
        />

        <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>CA Private Key PEM</label>
        <textarea
          className="w-full mb-4 p-3 rounded-lg text-sm font-mono"
          rows={8}
          value={keyPem}
          onChange={(e) => setKeyPem(e.target.value)}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
        />

        <button
          type="submit"
          className="px-4 py-2 rounded-lg text-white"
          style={{ background: 'var(--accent)' }}
          disabled={saving}
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      </form>
    </div>
  );
};
