import React from 'react';

interface PolicyEditorHeaderProps {
  editorMode: 'create' | 'edit';
  editorTargetId: string | null;
}

export const PolicyEditorHeader: React.FC<PolicyEditorHeaderProps> = ({
  editorMode,
  editorTargetId,
}) => (
  <div
    className="px-4 py-3 text-sm font-semibold"
    style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
  >
    <div>Policy Builder</div>
  </div>
);
