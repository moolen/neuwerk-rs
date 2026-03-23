import React from 'react';
import { IntegrationBasicsSection } from './IntegrationBasicsSection';
import { IntegrationCredentialsSection } from './IntegrationCredentialsSection';
import { IntegrationEditorActions } from './IntegrationEditorActions';
import { IntegrationEditorHeader } from './IntegrationEditorHeader';
import type { EditorMode, IntegrationForm } from '../types';

interface IntegrationEditorPanelProps {
  editorMode: EditorMode;
  selectedName: string | null;
  form: IntegrationForm;
  saving: boolean;
  editorError: string | null;
  tokenConfigured: boolean;
  onFormChange: (field: keyof IntegrationForm, value: string) => void;
  onReset: () => void;
  onSave: () => void;
  onDelete: () => void;
}

export const IntegrationEditorPanel: React.FC<IntegrationEditorPanelProps> = ({
  editorMode,
  selectedName,
  form,
  saving,
  editorError,
  tokenConfigured,
  onFormChange,
  onReset,
  onSave,
  onDelete,
}) => (
  <div
    className="rounded-[1.5rem] overflow-hidden"
    style={{
      background: 'var(--bg-glass)',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <IntegrationEditorHeader
      editorMode={editorMode}
      selectedName={selectedName}
      kind={form.kind}
      tokenConfigured={tokenConfigured}
      onDelete={onDelete}
    />

    <div className="p-5 space-y-5">
      <section
        className="rounded-[1.15rem] p-4 space-y-4 md:p-5"
        style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-subtle)' }}
      >
        <div className="space-y-1">
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            Connection Profile
          </h3>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Cluster identity, provider type, and kube-apiserver endpoint used for inventory sync.
          </p>
        </div>
        <IntegrationBasicsSection editorMode={editorMode} form={form} onFormChange={onFormChange} />
      </section>

      <section
        className="rounded-[1.15rem] p-4 space-y-4 md:p-5"
        style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-subtle)' }}
      >
        <div className="space-y-1">
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            Credentials
          </h3>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Certificate trust and service account material used to authenticate against Kubernetes.
          </p>
        </div>
        <IntegrationCredentialsSection
          editorMode={editorMode}
          form={form}
          onFormChange={onFormChange}
        />
      </section>

      {editorError && (
        <div
          className="rounded-[1rem] p-3 text-xs"
          style={{
            color: 'var(--red)',
            background: 'var(--red-bg)',
            border: '1px solid var(--red-border)',
          }}
        >
          {editorError}
        </div>
      )}

      <IntegrationEditorActions
        editorMode={editorMode}
        saving={saving}
        onReset={onReset}
        onSave={onSave}
      />
    </div>
  </div>
);
