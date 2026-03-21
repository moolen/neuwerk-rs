import { useEffect, useState } from 'react';
import {
  downloadClusterSysdump,
  createSsoProvider,
  deleteSsoProvider,
  generateTlsInterceptCa,
  getPerformanceModeStatus,
  getThreatIntelSettings,
  getTlsInterceptCaCertPem,
  getTlsInterceptCaStatus,
  listSsoProviders,
  testSsoProvider,
  updateThreatIntelSettings,
  updatePerformanceMode,
  updateSsoProvider,
  updateTlsInterceptCa,
} from '../../services/api';
import type {
  PerformanceModeStatus,
  SsoProviderView,
  ThreatIntelSettingsStatus,
  TlsInterceptCaStatus,
} from '../../types';
import { validateTlsInterceptCaInput } from './helpers';
import {
  buildSsoCreateRequest,
  buildSsoPatchRequest,
  emptySsoProviderDraft,
  ssoDraftFromProvider,
  type SsoProviderDraft,
  validateSsoProviderDraft,
} from './ssoForm';

export function useSettingsPage() {
  const [status, setStatus] = useState<TlsInterceptCaStatus | null>(null);
  const [performanceMode, setPerformanceMode] = useState<PerformanceModeStatus | null>(null);
  const [threatSettings, setThreatSettings] = useState<ThreatIntelSettingsStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [performanceModeSaving, setPerformanceModeSaving] = useState(false);
  const [threatSettingsSaving, setThreatSettingsSaving] = useState(false);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [sysdumpDownloading, setSysdumpDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');

  const [ssoProviders, setSsoProviders] = useState<SsoProviderView[]>([]);
  const [ssoLoading, setSsoLoading] = useState(true);
  const [ssoSaving, setSsoSaving] = useState(false);
  const [ssoDeletingId, setSsoDeletingId] = useState<string | null>(null);
  const [ssoTestingId, setSsoTestingId] = useState<string | null>(null);
  const [ssoError, setSsoError] = useState<string | null>(null);
  const [ssoSuccess, setSsoSuccess] = useState<string | null>(null);
  const [ssoDraft, setSsoDraft] = useState<SsoProviderDraft>(emptySsoProviderDraft());

  const refresh = async () => {
    try {
      setLoading(true);
      setError(null);
      const [current, perf, threat] = await Promise.all([
        getTlsInterceptCaStatus(),
        getPerformanceModeStatus(),
        getThreatIntelSettings(),
      ]);
      setStatus(current);
      setPerformanceMode(perf);
      setThreatSettings(threat);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const refreshSso = async (preferredId?: string) => {
    try {
      setSsoLoading(true);
      setSsoError(null);
      const next = await listSsoProviders();
      setSsoProviders(next);
      setSsoDraft((current) => {
        const selectedId = preferredId ?? current.id;
        if (selectedId) {
          const selected = next.find((provider) => provider.id === selectedId);
          if (selected) {
            return ssoDraftFromProvider(selected);
          }
        }
        if (!current.id && current.name.trim().length > 0) {
          return current;
        }
        return emptySsoProviderDraft();
      });
    } catch (err) {
      setSsoError(err instanceof Error ? err.message : 'Failed to load SSO providers');
    } finally {
      setSsoLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    void refreshSso();
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

  const downloadClusterBundle = async () => {
    setError(null);
    setSuccess(null);
    try {
      setSysdumpDownloading(true);
      const { blob, filename } = await downloadClusterSysdump();
      const objectUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download =
        filename ??
        `neuwerk-cluster-sysdump-${new Date().toISOString().replace(/[:.]/g, '-')}.tar.gz`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
      setSuccess('Cluster sysdump downloaded');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download cluster sysdump');
    } finally {
      setSysdumpDownloading(false);
    }
  };

  const savePerformanceMode = async (enabled: boolean) => {
    setError(null);
    setSuccess(null);
    try {
      setPerformanceModeSaving(true);
      const next = await updatePerformanceMode(enabled);
      setPerformanceMode(next);
      setSuccess(`Performance mode ${next.enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update performance mode');
    } finally {
      setPerformanceModeSaving(false);
    }
  };

  const saveThreatAnalysisEnabled = async (enabled: boolean) => {
    setError(null);
    setSuccess(null);
    try {
      setThreatSettingsSaving(true);
      const next = await updateThreatIntelSettings(enabled);
      setThreatSettings(next);
      setSuccess(`Threat analysis ${next.enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update threat analysis');
    } finally {
      setThreatSettingsSaving(false);
    }
  };

  const createNewSsoDraft = () => {
    setSsoError(null);
    setSsoSuccess(null);
    setSsoDraft(emptySsoProviderDraft());
  };

  const selectSsoProvider = (id: string) => {
    const selected = ssoProviders.find((provider) => provider.id === id);
    if (!selected) {
      return;
    }
    setSsoError(null);
    setSsoSuccess(null);
    setSsoDraft(ssoDraftFromProvider(selected));
  };

  const saveSsoProviderDraft = async () => {
    setSsoError(null);
    setSsoSuccess(null);

    const validationError = validateSsoProviderDraft(ssoDraft);
    if (validationError) {
      setSsoError(validationError);
      return;
    }

    try {
      setSsoSaving(true);
      let saved: SsoProviderView;
      if (ssoDraft.id) {
        saved = await updateSsoProvider(ssoDraft.id, buildSsoPatchRequest(ssoDraft));
      } else {
        saved = await createSsoProvider(buildSsoCreateRequest(ssoDraft));
      }
      setSsoDraft(ssoDraftFromProvider(saved));
      await refreshSso(saved.id);
      setSsoSuccess(`Provider ${saved.name} saved`);
    } catch (err) {
      setSsoError(err instanceof Error ? err.message : 'Failed to save SSO provider');
    } finally {
      setSsoSaving(false);
    }
  };

  const deleteSsoProviderById = async (id: string) => {
    setSsoError(null);
    setSsoSuccess(null);
    try {
      setSsoDeletingId(id);
      await deleteSsoProvider(id);
      if (ssoDraft.id === id) {
        setSsoDraft(emptySsoProviderDraft());
      }
      await refreshSso();
      setSsoSuccess('Provider deleted');
    } catch (err) {
      setSsoError(err instanceof Error ? err.message : 'Failed to delete SSO provider');
    } finally {
      setSsoDeletingId(null);
    }
  };

  const testSsoProviderById = async (id: string) => {
    setSsoError(null);
    setSsoSuccess(null);
    try {
      setSsoTestingId(id);
      const result = await testSsoProvider(id);
      if (result.ok) {
        setSsoSuccess(result.details);
      } else {
        setSsoError(result.details);
      }
    } catch (err) {
      setSsoError(err instanceof Error ? err.message : 'Failed to test SSO provider');
    } finally {
      setSsoTestingId(null);
    }
  };

  return {
    status,
    performanceMode,
    threatSettings,
    loading,
    performanceModeSaving,
    threatSettingsSaving,
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
    sysdumpDownloading,
    downloadClusterBundle,
    savePerformanceMode,
    saveThreatAnalysisEnabled,
    ssoProviders,
    ssoLoading,
    ssoSaving,
    ssoDeletingId,
    ssoTestingId,
    ssoError,
    ssoSuccess,
    ssoDraft,
    setSsoDraft,
    refreshSso,
    createNewSsoDraft,
    selectSsoProvider,
    saveSsoProviderDraft,
    deleteSsoProviderById,
    testSsoProviderById,
  };
}
