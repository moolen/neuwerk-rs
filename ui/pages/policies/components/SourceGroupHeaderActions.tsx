import React from 'react';
import { Copy, MoveDown, MoveUp, Trash2 } from 'lucide-react';

interface SourceGroupHeaderActionsProps {
  groupIndex: number;
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
}

export const SourceGroupHeaderActions: React.FC<SourceGroupHeaderActionsProps> = ({
  groupIndex,
  duplicateGroup,
  moveGroup,
  deleteGroup,
}) => (
  <div className="flex items-center gap-1 shrink-0">
    <button
      type="button"
      onClick={() => moveGroup(groupIndex, -1)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Move up"
    >
      <MoveUp className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => moveGroup(groupIndex, 1)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Move down"
    >
      <MoveDown className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => duplicateGroup(groupIndex)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Duplicate group"
    >
      <Copy className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => deleteGroup(groupIndex)}
      className="p-2 rounded"
      style={{ color: 'var(--red)' }}
      title="Delete group"
    >
      <Trash2 className="w-4 h-4" />
    </button>
  </div>
);
