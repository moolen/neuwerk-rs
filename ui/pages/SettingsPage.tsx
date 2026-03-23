import React from 'react';
import { PageLayout } from '../components/layout/PageLayout';
import { PerformanceModeCard } from './settings/components/PerformanceModeCard';
import { SettingsStatusCard } from './settings/components/SettingsStatusCard';
import { SsoProvidersForm } from './settings/components/SsoProvidersForm';
import { SupportBundleCard } from './settings/components/SupportBundleCard';
import { ThreatAnalysisCard } from './settings/components/ThreatAnalysisCard';
import { TlsInterceptCaForm } from './settings/components/TlsInterceptCaForm';
import { useSettingsPage } from './settings/useSettingsPage';

export const SettingsPage: React.FC = () => {
  const {
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
    createNewSsoDraft,
    selectSsoProvider,
    saveSsoProviderDraft,
    deleteSsoProviderById,
    testSsoProviderById,
  } = useSettingsPage();
  const enabledProviderCount = ssoProviders.filter((provider) => provider.enabled).length;
  const identityProviderSummary =
    ssoProviders.length === 0
      ? 'No identity providers configured'
      : `${enabledProviderCount}/${ssoProviders.length} identity provider${ssoProviders.length === 1 ? '' : 's'} enabled`;
  const postureCards = [
    {
      label: 'Performance mode',
      value: performanceMode?.enabled ? 'Enabled' : 'Disabled',
      detail: `Source: ${performanceMode?.source ?? '-'}`,
      accent: performanceMode?.enabled ? 'var(--green)' : 'var(--amber)',
      background: performanceMode?.enabled ? 'var(--green-bg)' : 'var(--amber-bg)',
      border: performanceMode?.enabled ? 'var(--green-border)' : 'var(--amber-border)',
    },
    {
      label: 'Threat analysis',
      value: threatSettings?.enabled ? 'Enabled' : 'Disabled',
      detail: `Threshold: ${threatSettings?.alert_threshold ?? '-'}`,
      accent: threatSettings?.enabled ? 'var(--green)' : 'var(--amber)',
      background: threatSettings?.enabled ? 'var(--green-bg)' : 'var(--amber-bg)',
      border: threatSettings?.enabled ? 'var(--green-border)' : 'var(--amber-border)',
    },
    {
      label: 'TLS intercept readiness',
      value: status?.configured ? 'Configured' : 'Not configured',
      detail: status?.fingerprint_sha256 ? 'Fingerprint available' : 'No trust material loaded',
      accent: status?.configured ? 'var(--accent)' : 'var(--text-secondary)',
      background: status?.configured ? 'rgba(79,110,247,0.12)' : 'var(--bg-glass-subtle)',
      border: status?.configured ? 'rgba(79,110,247,0.22)' : 'var(--border-glass)',
    },
  ];

  return (
    <PageLayout
      title="Settings"
      description="Manage performance mode, threat analysis, DPI TLS interception CA material, and SSO providers."
    >
      <section
        className="rounded-[1.5rem] p-5 space-y-4"
        style={{
          background: 'var(--bg-glass)',
          border: '1px solid var(--border-glass)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.26em]" style={{ color: 'var(--text-muted)' }}>
              Control plane posture
            </div>
            <h2 className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
              Current enforcement and trust posture
            </h2>
            <p className="mt-1 text-sm max-w-[44rem]" style={{ color: 'var(--text-secondary)' }}>
              Scan the global runtime toggles, threat pipeline state, and TLS intercept readiness before editing individual sections.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)', color: 'var(--text-secondary)' }}
          >
            {identityProviderSummary}
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          {postureCards.map((card) => (
            <div
              key={card.label}
              className="rounded-[1.15rem] p-4"
              style={{
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-glass)',
              }}
            >
              <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                {card.label}
              </div>
              <div
                className="mt-3 inline-flex px-2.5 py-1 rounded-full text-xs font-semibold"
                style={{
                  color: card.accent,
                  background: card.background,
                  border: `1px solid ${card.border}`,
                }}
              >
                {card.value}
              </div>
              <div className="mt-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
                {card.detail}
              </div>
            </div>
          ))}
        </div>
      </section>

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

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Runtime controls
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Core control-plane switches
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            These switches change what Neuwerk exposes and analyzes across the cluster.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(18rem,0.9fr)]">
          <PerformanceModeCard
            status={performanceMode}
            loading={loading}
            saving={performanceModeSaving}
            onToggle={(enabled) => void savePerformanceMode(enabled)}
          />

          <ThreatAnalysisCard
            status={threatSettings}
            loading={loading}
            saving={threatSettingsSaving}
            onToggle={(enabled) => void saveThreatAnalysisEnabled(enabled)}
          />

          <SettingsStatusCard status={status} loading={loading} onRefresh={() => void refresh()} />
        </div>
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Trust material
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            TLS intercept trust and recovery artifacts
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Maintain the CA that powers DPI TLS intercept flows and keep the cluster support bundle close at hand for incident response.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(20rem,0.9fr)]">
          <TlsInterceptCaForm
            certPem={certPem}
            keyPem={keyPem}
            saving={saving}
            generating={generating}
            downloading={downloading}
            canDownload={Boolean(status?.configured)}
            onCertPemChange={setCertPem}
            onKeyPemChange={setKeyPem}
            onSubmit={() => void submit()}
            onGenerate={() => void generate()}
            onDownload={() => void downloadCert()}
          />

          <SupportBundleCard
            downloading={sysdumpDownloading}
            onDownload={() => void downloadClusterBundle()}
          />
        </div>
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Identity providers
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Login sources and role defaults
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Curate the provider directory that appears on the login page and control which roles new sessions receive.
          </p>
        </div>

        <SsoProvidersForm
          providers={ssoProviders}
          loading={ssoLoading}
          saving={ssoSaving}
          deletingId={ssoDeletingId}
          testingId={ssoTestingId}
          error={ssoError}
          success={ssoSuccess}
          draft={ssoDraft}
          onSelect={selectSsoProvider}
          onCreateNew={createNewSsoDraft}
          onDraftChange={setSsoDraft}
          onSave={() => void saveSsoProviderDraft()}
          onDelete={(id) => void deleteSsoProviderById(id)}
          onTest={(id) => void testSsoProviderById(id)}
        />
      </section>
    </PageLayout>
  );
};
