import React from 'react';

interface TlsInterceptCaFormProps {
  certPem: string;
  keyPem: string;
  saving: boolean;
  generating: boolean;
  downloading: boolean;
  canDownload: boolean;
  onCertPemChange: (value: string) => void;
  onKeyPemChange: (value: string) => void;
  onSubmit: () => void;
  onGenerate: () => void;
  onDownload: () => void;
}

export const TlsInterceptCaForm: React.FC<TlsInterceptCaFormProps> = ({
  certPem,
  keyPem,
  saving,
  generating,
  downloading,
  canDownload,
  onCertPemChange,
  onKeyPemChange,
  onSubmit,
  onGenerate,
  onDownload,
}) => (
  <form
    onSubmit={(event) => {
      event.preventDefault();
      onSubmit();
    }}
    className="rounded-xl p-6"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--text)' }}>
      DPI / TLS Intercept CA
    </h2>
    <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
      Generate a self-signed CA for DPI, or paste your own certificate and key pair.
    </p>
    <div className="mb-5 flex flex-wrap items-center gap-3">
      <button
        type="button"
        className="px-4 py-2 rounded-lg text-sm font-semibold text-white shadow-sm transition-colors"
        style={{
          minHeight: 40,
          background: 'var(--accent)',
          cursor: saving || generating || downloading ? 'not-allowed' : 'pointer',
          opacity: saving || generating || downloading ? 0.65 : 1,
        }}
        disabled={saving || generating || downloading}
        onClick={onGenerate}
      >
        {generating ? 'Generating...' : 'Generate DPI Keypair'}
      </button>
      <button
        type="button"
        className="px-4 py-2 rounded-lg text-sm font-semibold shadow-sm transition-colors"
        style={{
          minHeight: 40,
          background: 'var(--bg-card)',
          color: 'var(--text)',
          border: '1px solid var(--border-glass)',
          cursor: saving || generating || downloading || !canDownload ? 'not-allowed' : 'pointer',
          opacity: saving || generating || downloading || !canDownload ? 0.65 : 1,
        }}
        disabled={saving || generating || downloading || !canDownload}
        onClick={onDownload}
      >
        {downloading ? 'Downloading...' : 'Download CA Certificate'}
      </button>
    </div>

    <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
      CA Certificate PEM
    </label>
    <textarea
      className="w-full mb-4 p-3 rounded-lg text-sm font-mono"
      rows={5}
      value={certPem}
      onChange={(e) => onCertPemChange(e.target.value)}
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
    />

    <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
      CA Private Key PEM
    </label>
    <textarea
      className="w-full mb-4 p-3 rounded-lg text-sm font-mono"
      rows={5}
      value={keyPem}
      onChange={(e) => onKeyPemChange(e.target.value)}
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
    />

    <div className="flex items-center justify-end gap-3">
      <button
        type="submit"
        className="px-4 py-2 rounded-lg text-sm font-semibold text-white shadow-sm transition-colors"
        style={{
          minHeight: 40,
          background: 'var(--accent)',
          cursor: saving || generating || downloading ? 'not-allowed' : 'pointer',
          opacity: saving || generating || downloading ? 0.65 : 1,
        }}
        disabled={saving || generating || downloading}
      >
        {saving ? 'Saving...' : 'Save'}
      </button>
    </div>
  </form>
);
