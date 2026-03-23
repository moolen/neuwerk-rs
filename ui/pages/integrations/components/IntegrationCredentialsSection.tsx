import React from 'react';
import type { EditorMode, IntegrationForm } from '../types';

interface IntegrationCredentialsSectionProps {
  editorMode: EditorMode;
  form: IntegrationForm;
  onFormChange: (field: keyof IntegrationForm, value: string) => void;
}

export const IntegrationCredentialsSection: React.FC<IntegrationCredentialsSectionProps> = ({
  editorMode,
  form,
  onFormChange,
}) => (
  <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        kube-apiserver CA Certificate (PEM)
      </label>
      <textarea
        value={form.caCertPem}
        onChange={(e) => onFormChange('caCertPem', e.target.value)}
        rows={6}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="-----BEGIN CERTIFICATE-----"
      />
      <p className="mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
        Paste the cluster CA chain Neuwerk should trust when connecting to the API server.
      </p>
    </div>

    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Service Account Token
      </label>
      <textarea
        value={form.serviceAccountToken}
        onChange={(e) => onFormChange('serviceAccountToken', e.target.value)}
        rows={4}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="eyJhbGciOi..."
      />
      {editorMode === 'edit' && (
        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
          Token is write-only; provide a replacement token when updating.
        </p>
      )}
    </div>
  </div>
);
