import React from 'react';
import type { EditorMode, IntegrationForm } from '../types';

interface IntegrationBasicsSectionProps {
  editorMode: EditorMode;
  form: IntegrationForm;
  onFormChange: (field: keyof IntegrationForm, value: string) => void;
}

export const IntegrationBasicsSection: React.FC<IntegrationBasicsSectionProps> = ({
  editorMode,
  form,
  onFormChange,
}) => (
  <div className="grid gap-4 md:grid-cols-2">
    <div className="md:col-span-1">
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Name
      </label>
      <input
        value={form.name}
        onChange={(e) => onFormChange('name', e.target.value)}
        disabled={editorMode === 'edit'}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="prod-kubernetes"
      />
    </div>

    <div className="md:col-span-1">
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Integration Type
      </label>
      <input
        value={form.kind}
        disabled
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-secondary)',
        }}
      />
    </div>

    <div className="md:col-span-2">
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        kube-apiserver URL
      </label>
      <input
        value={form.apiServerUrl}
        onChange={(e) => onFormChange('apiServerUrl', e.target.value)}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="https://10.0.0.1:6443"
      />
      <p className="mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
        Point this at the control-plane endpoint reachable from the Neuwerk node running the selector sync.
      </p>
    </div>
  </div>
);
