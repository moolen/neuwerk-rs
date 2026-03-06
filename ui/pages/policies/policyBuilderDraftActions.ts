import type { PolicyCreateRequest } from '../../types';
import {
  addGroupToDraft,
  addRuleToGroupInDraft,
  deleteGroupInDraft,
  deleteRuleInGroupInDraft,
  duplicateGroupInDraft,
  duplicateRuleInGroupInDraft,
  moveGroupInDraft,
  moveRuleInGroupInDraft,
} from './policyBuilderDraftMutations';

interface PolicyBuilderDraftActionOptions {
  updateDraft: (mutator: (next: PolicyCreateRequest) => void) => void;
}

export function createPolicyBuilderDraftActions(options: PolicyBuilderDraftActionOptions): {
  addGroup: () => void;
  duplicateGroup: (groupIndex: number) => void;
  moveGroup: (groupIndex: number, direction: -1 | 1) => void;
  deleteGroup: (groupIndex: number) => void;
  addRule: (groupIndex: number) => void;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
} {
  const { updateDraft } = options;
  return {
    addGroup: () => {
      updateDraft((next) => {
        addGroupToDraft(next);
      });
    },
    duplicateGroup: (groupIndex) => {
      updateDraft((next) => {
        duplicateGroupInDraft(next, groupIndex);
      });
    },
    moveGroup: (groupIndex, direction) => {
      updateDraft((next) => {
        moveGroupInDraft(next, groupIndex, direction);
      });
    },
    deleteGroup: (groupIndex) => {
      updateDraft((next) => {
        deleteGroupInDraft(next, groupIndex);
      });
    },
    addRule: (groupIndex) => {
      updateDraft((next) => {
        addRuleToGroupInDraft(next, groupIndex);
      });
    },
    duplicateRule: (groupIndex, ruleIndex) => {
      updateDraft((next) => {
        duplicateRuleInGroupInDraft(next, groupIndex, ruleIndex);
      });
    },
    moveRule: (groupIndex, ruleIndex, direction) => {
      updateDraft((next) => {
        moveRuleInGroupInDraft(next, groupIndex, ruleIndex, direction);
      });
    },
    deleteRule: (groupIndex, ruleIndex) => {
      updateDraft((next) => {
        deleteRuleInGroupInDraft(next, groupIndex, ruleIndex);
      });
    },
  };
}
