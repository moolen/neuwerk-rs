import React from 'react';
import { Copy, MoveDown, MoveUp, Trash2 } from 'lucide-react';

import type { RuleEditorActionsProps } from './ruleEditorTypes';

interface RuleHeaderActionsProps extends RuleEditorActionsProps {
  groupIndex: number;
  ruleIndex: number;
}

export const RuleHeaderActions: React.FC<RuleHeaderActionsProps> = ({
  groupIndex,
  ruleIndex,
  moveRule,
  duplicateRule,
  deleteRule,
}) => (
  <div className="flex items-center gap-1">
    <button
      type="button"
      onClick={() => moveRule(groupIndex, ruleIndex, -1)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Move up"
    >
      <MoveUp className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => moveRule(groupIndex, ruleIndex, 1)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Move down"
    >
      <MoveDown className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => duplicateRule(groupIndex, ruleIndex)}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Duplicate"
    >
      <Copy className="w-4 h-4" />
    </button>
    <button
      type="button"
      onClick={() => deleteRule(groupIndex, ruleIndex)}
      className="p-2 rounded"
      style={{ color: 'var(--red)' }}
      title="Delete"
    >
      <Trash2 className="w-4 h-4" />
    </button>
  </div>
);
