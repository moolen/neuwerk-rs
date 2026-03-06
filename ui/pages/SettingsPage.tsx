import React from 'react';
import { SettingsStatusCard } from './settings/components/SettingsStatusCard';
import { TlsInterceptCaForm } from './settings/components/TlsInterceptCaForm';
import { useSettingsPage } from './settings/useSettingsPage';

export const SettingsPage: React.FC = () => {
  const {
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
  } = useSettingsPage();

  return (
    <div className="p-6 space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-1" style={{ color: 'var(--text)' }}>Settings</h1>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Manage DPI TLS interception CA material.
        </p>
      </div>

      <SettingsStatusCard status={status} loading={loading} onRefresh={() => void refresh()} />

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

      <div>
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
      </div>
    </div>
  );
};
