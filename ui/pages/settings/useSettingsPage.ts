import { useEffect, useState } from 'react';
import {
  generateTlsInterceptCa,
  getTlsInterceptCaCertPem,
  getTlsInterceptCaStatus,
  updateTlsInterceptCa,
} from '../../services/api';
import type { TlsInterceptCaStatus } from '../../types';
import { validateTlsInterceptCaInput } from './helpers';

export function useSettingsPage() {
  const [status, setStatus] = useState<TlsInterceptCaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');

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

  useEffect(() => {
    void refresh();
  }, []);

  const submit = async () => {
    setError(null);
    setSuccess(null);

    const validationError = validateTlsInterceptCaInput(certPem, keyPem);
    if (validationError) {
      setError(validationError);
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

  const generate = async () => {
    setError(null);
    setSuccess(null);
    try {
      setGenerating(true);
      const next = await generateTlsInterceptCa();
      setStatus(next);
      setCertPem('');
      setKeyPem('');
      setSuccess('DPI key material generated and saved');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate DPI key material');
    } finally {
      setGenerating(false);
    }
  };

  const downloadCert = async () => {
    setError(null);
    setSuccess(null);
    try {
      setDownloading(true);
      const certPem = await getTlsInterceptCaCertPem();
      const blob = new Blob([certPem], { type: 'application/x-pem-file' });
      const objectUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = `neuwerk-dpi-root-ca-${new Date().toISOString().replace(/[:.]/g, '-')}.crt`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
      setSuccess('TLS intercept CA certificate downloaded');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download TLS intercept CA certificate');
    } finally {
      setDownloading(false);
    }
  };

  return {
    status,
    loading,
    saving,
    generating,
    downloading,
    error,
    success,
    certPem,
    keyPem,
    setCertPem,
    setKeyPem,
    refresh,
    submit,
    generate,
    downloadCert,
  };
}
