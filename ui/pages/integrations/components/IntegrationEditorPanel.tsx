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
  onFormChange,
  onReset,
  onSave,
  onDelete,
}) => (
  <div
    className="rounded-xl overflow-hidden"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <IntegrationEditorHeader editorMode={editorMode} selectedName={selectedName} onDelete={onDelete} />

    <div className="p-4 space-y-4">
      <IntegrationBasicsSection editorMode={editorMode} form={form} onFormChange={onFormChange} />

      <IntegrationCredentialsSection
        editorMode={editorMode}
        form={form}
        onFormChange={onFormChange}
      />

      {editorError && (
        <div className="text-xs" style={{ color: 'var(--red)' }}>
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
