import React from 'react';
import { X } from 'lucide-react';

import { isPolicySaveDisabled } from './policiesPageHelpers';

interface PolicySourceGroupEditorOverlayProps {
  children: React.ReactNode;
  open: boolean;
  policyLabel: string;
  saving: boolean;
  sourceGroupLabel: string;
  validationIssueCount: number;
  onClose: () => void;
  onSave: () => void;
}

export const PolicySourceGroupEditorOverlay: React.FC<PolicySourceGroupEditorOverlayProps> = ({
  children,
  open,
  policyLabel,
  saving,
  sourceGroupLabel,
  validationIssueCount,
  onClose,
  onSave,
}) => {
  if (!open) return null;

  const saveDisabled = isPolicySaveDisabled(saving, validationIssueCount);

  return (
    <div
      data-overlay-anchor="policies-page-root"
      className="absolute inset-0 z-20"
    >
      <section
        data-overlay-surface="full-page"
        className="mx-auto flex h-full w-full max-w-[92rem] flex-col overflow-hidden rounded-[1.6rem]"
        style={{
          background: 'linear-gradient(180deg, color-mix(in srgb, var(--bg-glass-strong) 94%, var(--bg) 6%), rgba(255,255,255,0.04))',
          border: '1px solid var(--border-glass)',
          boxShadow: '0 28px 70px rgba(5, 12, 24, 0.26)',
          backdropFilter: 'blur(16px)',
        }}
      >
        <div
          className="flex flex-col gap-4 border-b px-4 py-4 sm:px-5 sm:py-5 lg:flex-row lg:items-start lg:justify-between"
          style={{ borderColor: 'var(--border-glass)' }}
        >
          <div className="space-y-1.5">
            <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
              {policyLabel}
            </div>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
              Editing {sourceGroupLabel}
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-2 self-start rounded-xl px-3 py-2 text-sm"
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
            }}
          >
            <X className="h-4 w-4" />
            Close
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-5">{children}</div>

        <div
          className="flex flex-col gap-3 border-t px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"
          style={{ borderColor: 'var(--border-glass)' }}
        >
          <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {validationIssueCount
              ? `Resolve ${validationIssueCount} validation issues before saving.`
              : 'Save persists the selected policy with the edited source-group changes.'}
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl px-4 py-2 text-sm"
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              Keep browsing
            </button>
            <button
              type="button"
              disabled={saveDisabled}
              onClick={onSave}
              className="rounded-xl px-4 py-2 text-sm text-white"
              style={{
                background: saveDisabled ? 'var(--text-muted)' : 'var(--accent)',
                cursor: saveDisabled ? 'not-allowed' : 'pointer',
              }}
            >
              {saving ? 'Saving...' : 'Save policy'}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
};
