import React from 'react';
import { Trash2 } from 'lucide-react';
import type { EditorMode } from '../types';

interface IntegrationEditorHeaderProps {
  editorMode: EditorMode;
  selectedName: string | null;
  kind: string;
  tokenConfigured: boolean;
  onDelete: () => void;
}

export const IntegrationEditorHeader: React.FC<IntegrationEditorHeaderProps> = ({
  editorMode,
  selectedName,
  kind,
  tokenConfigured,
  onDelete,
}) => (
  <div
    className="px-5 py-4"
    style={{ borderBottom: '1px solid var(--border-glass)' }}
  >
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase tracking-[0.18em]"
            style={{
              color: 'var(--accent)',
              background: 'rgba(79,110,247,0.12)',
              border: '1px solid rgba(79,110,247,0.2)',
            }}
          >
            {editorMode === 'create' ? 'Create' : 'Editing'}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-[11px] font-semibold"
            style={{
              color: 'var(--text-secondary)',
              background: 'var(--bg-glass-subtle)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {kind}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-[11px] font-semibold"
            style={{
              color: tokenConfigured ? 'var(--green)' : 'var(--amber)',
              background: tokenConfigured ? 'var(--green-bg)' : 'var(--amber-bg)',
              border: tokenConfigured
                ? '1px solid var(--green-border)'
                : '1px solid var(--amber-border)',
            }}
          >
            {tokenConfigured ? 'Token ready' : 'Token required'}
          </span>
        </div>

        <div>
          <div className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            {editorMode === 'create' ? 'New integration draft' : selectedName ?? 'Integration editor'}
          </div>
          <div className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
            {editorMode === 'create'
              ? 'Define the cluster endpoint and credentials for a new inventory source.'
              : `Editing ${selectedName ?? 'integration'} for policy-driven dynamic source resolution.`}
          </div>
        </div>
      </div>

      {editorMode === 'edit' && (
        <button
          onClick={onDelete}
          className="px-3 py-2 text-xs rounded-xl flex items-center gap-1 self-start"
          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
        >
          <Trash2 className="w-3 h-3" />
          Delete
        </button>
      )}
    </div>
  </div>
);
