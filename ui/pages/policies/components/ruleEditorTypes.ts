import type { PolicyRule } from '../../../types';
import type { UpdateDraft } from './formTypes';

export interface RuleEditorContextProps {
  groupIndex: number;
  ruleIndex: number;
  rule: PolicyRule;
  updateDraft: UpdateDraft;
}

export interface RuleEditorActionsProps {
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
}
