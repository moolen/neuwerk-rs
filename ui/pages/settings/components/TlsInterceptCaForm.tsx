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
    className="rounded-[1.5rem] p-6"
    style={{
      background: 'var(--bg-glass)',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: canDownload ? 'var(--green)' : 'var(--amber)',
              background: canDownload ? 'var(--green-bg)' : 'var(--amber-bg)',
              border: canDownload ? '1px solid var(--green-border)' : '1px solid var(--amber-border)',
            }}
          >
            {canDownload ? 'Configured' : 'Awaiting CA'}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{
              color: 'var(--text-secondary)',
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            Trust material
          </span>
        </div>
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            DPI / TLS Intercept CA
          </h2>
          <p className="text-sm mt-1 max-w-[42rem]" style={{ color: 'var(--text-secondary)' }}>
            Generate a self-signed CA for DPI, or paste your own certificate and key pair for cluster-wide TLS intercept trust.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          className="px-4 py-2 rounded-xl text-sm font-semibold text-white shadow-sm transition-colors"
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
          className="px-4 py-2 rounded-xl text-sm font-semibold shadow-sm transition-colors"
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
    </div>

    <div className="grid gap-4 mt-6 xl:grid-cols-2">
      <div>
        <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
          CA Certificate PEM
        </label>
        <textarea
          className="w-full p-3 rounded-xl text-sm font-mono"
          rows={11}
          value={certPem}
          onChange={(e) => onCertPemChange(e.target.value)}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
        />
      </div>
      <div>
        <label className="block text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
          CA Private Key PEM
        </label>
        <textarea
          className="w-full p-3 rounded-xl text-sm font-mono"
          rows={11}
          value={keyPem}
          onChange={(e) => onKeyPemChange(e.target.value)}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-glass)', color: 'var(--text)' }}
        />
      </div>
    </div>

    <div className="flex items-center justify-end gap-3 mt-4">
      <button
        type="submit"
        className="px-4 py-2 rounded-xl text-sm font-semibold text-white shadow-sm transition-colors"
        style={{
          minHeight: 40,
          background: 'var(--accent)',
          cursor: saving || generating || downloading ? 'not-allowed' : 'pointer',
          opacity: saving || generating || downloading ? 0.65 : 1,
        }}
        disabled={saving || generating || downloading}
      >
        {saving ? 'Saving...' : 'Save Trust Material'}
      </button>
    </div>
  </form>
);
