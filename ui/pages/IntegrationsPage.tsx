import React from 'react';
import { IntegrationEditorPanel } from './integrations/components/IntegrationEditorPanel';
import { IntegrationsHeader } from './integrations/components/IntegrationsHeader';
import { IntegrationsListPanel } from './integrations/components/IntegrationsListPanel';
import { useIntegrationsPage } from './integrations/useIntegrationsPage';

export const IntegrationsPage: React.FC = () => {
  const {
    integrations,
    selectedName,
    editorMode,
    form,
    loading,
    saving,
    error,
    editorError,
    loadIntegrations,
    selectIntegration,
    createNewIntegration,
    saveIntegration,
    deleteSelectedIntegration,
    setFormField,
  } = useIntegrationsPage();

  return (
    <div className="space-y-6">
      <IntegrationsHeader onRefresh={() => void loadIntegrations()} onCreateNew={createNewIntegration} />

      {error && (
        <div
          className="rounded-lg p-4"
          style={{
            background: 'var(--red-bg)',
            border: '1px solid var(--red-border)',
            color: 'var(--red)',
          }}
        >
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1">
          <IntegrationsListPanel
            loading={loading}
            integrations={integrations}
            selectedName={selectedName}
            onSelect={(name) => void selectIntegration(name)}
          />
        </div>

        <div className="xl:col-span-2">
          <IntegrationEditorPanel
            editorMode={editorMode}
            selectedName={selectedName}
            form={form}
            saving={saving}
            editorError={editorError}
            onFormChange={setFormField}
            onReset={createNewIntegration}
            onSave={() => void saveIntegration()}
            onDelete={() => void deleteSelectedIntegration()}
          />
        </div>
      </div>
    </div>
  );
};
