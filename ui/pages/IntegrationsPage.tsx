import React from 'react';
import { Plus, RefreshCw } from 'lucide-react';
import { PageLayout } from '../components/layout/PageLayout';
import { IntegrationEditorPanel } from './integrations/components/IntegrationEditorPanel';
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
  const selectedIntegration =
    integrations.find((integration) => integration.name === selectedName) ?? null;
  const tokenConfigured =
    editorMode === 'edit'
      ? Boolean(selectedIntegration?.token_configured)
      : form.serviceAccountToken.trim().length > 0;

  return (
    <PageLayout
      title="Integrations"
      description="Configure external inventory providers used by policy dynamic source selectors."
      actions={
        <div className="flex flex-wrap items-center gap-3 lg:justify-end">
          <button
            onClick={() => void loadIntegrations()}
            className="px-3 py-2 text-sm rounded-xl border"
            style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-secondary)' }}
          >
            <span className="flex items-center gap-2">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </span>
          </button>
          <button
            onClick={createNewIntegration}
            className="px-4 py-2 text-white rounded-xl flex items-center space-x-2 transition-colors"
            style={{ background: 'var(--accent)' }}
          >
            <Plus className="w-4 h-4" />
            <span>New Integration</span>
          </button>
        </div>
      }
    >

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

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(18rem,22rem)_minmax(0,1fr)]">
        <div>
          <IntegrationsListPanel
            loading={loading}
            integrations={integrations}
            selectedName={selectedName}
            onSelect={(name) => void selectIntegration(name)}
          />
        </div>

        <div>
          <IntegrationEditorPanel
            editorMode={editorMode}
            selectedName={selectedName}
            form={form}
            saving={saving}
            editorError={editorError}
            tokenConfigured={tokenConfigured}
            onFormChange={setFormField}
            onReset={createNewIntegration}
            onSave={() => void saveIntegration()}
            onDelete={() => void deleteSelectedIntegration()}
          />
        </div>
      </div>
    </PageLayout>
  );
};
