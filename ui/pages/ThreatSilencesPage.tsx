import React from 'react';

import { PageLayout } from '../components/layout/PageLayout';
import type { ThreatIndicatorType, ThreatSilenceKind } from '../types';
import { CreateThreatSilenceModal } from './threat-intel/components/CreateThreatSilenceModal';
import { ThreatSilencesPanel } from './threat-intel/components/ThreatSilencesPanel';
import { useThreatSilencesPage } from './threat-intel/useThreatSilencesPage';

interface SilenceDraftState {
  title: string;
  description: string;
  kind: ThreatSilenceKind;
  indicatorType: ThreatIndicatorType;
  value: string;
  reason: string;
  lockKind: boolean;
  lockIndicatorType: boolean;
}

export const ThreatSilencesPage: React.FC = () => {
  const { silences, loading, error, deletingSilenceId, silenceSaving, createSilence, deleteSilence } =
    useThreatSilencesPage();
  const [silenceDraft, setSilenceDraft] = React.useState<SilenceDraftState | null>(null);

  const openManualSilence = () => {
    setSilenceDraft({
      title: 'Add silence',
      description: 'Create a global silence for an exact indicator or a hostname regex.',
      kind: 'exact',
      indicatorType: 'hostname',
      value: '',
      reason: '',
      lockKind: false,
      lockIndicatorType: false,
    });
  };

  const submitSilence = async () => {
    if (!silenceDraft) {
      return;
    }
    await createSilence({
      kind: silenceDraft.kind,
      indicator_type: silenceDraft.kind === 'exact' ? silenceDraft.indicatorType : undefined,
      value: silenceDraft.value,
      reason: silenceDraft.reason.trim() || undefined,
    });
    setSilenceDraft(null);
  };

  return (
    <PageLayout
      title="Silences"
      description="Manage global suppressions applied before new findings are created."
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

      <ThreatSilencesPanel
        items={silences}
        loading={loading}
        deletingId={deletingSilenceId}
        onDelete={(id) => void deleteSilence(id)}
        onCreateManual={openManualSilence}
      />

      <CreateThreatSilenceModal
        open={silenceDraft !== null}
        title={silenceDraft?.title ?? ''}
        description={silenceDraft?.description ?? ''}
        kind={silenceDraft?.kind ?? 'exact'}
        indicatorType={silenceDraft?.indicatorType ?? 'hostname'}
        value={silenceDraft?.value ?? ''}
        reason={silenceDraft?.reason ?? ''}
        saving={silenceSaving}
        lockKind={silenceDraft?.lockKind}
        lockIndicatorType={silenceDraft?.lockIndicatorType}
        onKindChange={(kind) =>
          setSilenceDraft((current) =>
            current
              ? {
                  ...current,
                  kind,
                  indicatorType: kind === 'hostname_regex' ? 'hostname' : current.indicatorType,
                }
              : current,
          )
        }
        onIndicatorTypeChange={(indicatorType) =>
          setSilenceDraft((current) => (current ? { ...current, indicatorType } : current))
        }
        onValueChange={(value) =>
          setSilenceDraft((current) => (current ? { ...current, value } : current))
        }
        onReasonChange={(reason) =>
          setSilenceDraft((current) => (current ? { ...current, reason } : current))
        }
        onClose={() => setSilenceDraft(null)}
        onSubmit={() => void submitSilence()}
      />
    </PageLayout>
  );
};
