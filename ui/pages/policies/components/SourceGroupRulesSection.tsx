import React from 'react';

import type {
  SourceGroupContextProps,
} from './sourceGroupTypes';
import { SourceGroupRulesEmptyState } from './SourceGroupRulesEmptyState';
import { SourceGroupRulesList } from './SourceGroupRulesList';
import { SourceGroupRulesToolbar } from './SourceGroupRulesToolbar';

type SourceGroupRulesSectionProps = Pick<
  SourceGroupContextProps,
  'group' | 'groupIndex' | 'updateDraft'
> & {
    addRule: (groupIndex: number) => void;
    duplicateRule: (groupIndex: number, ruleIndex: number) => void;
    moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
    deleteRule: (groupIndex: number, ruleIndex: number) => void;
  };

export const SourceGroupRulesSection: React.FC<SourceGroupRulesSectionProps> = ({
  group,
  groupIndex,
  updateDraft,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => (
  <div className="space-y-3">
    <SourceGroupRulesToolbar
      groupIndex={groupIndex}
      addRule={addRule}
    />

    <SourceGroupRulesList
      group={group}
      groupIndex={groupIndex}
      updateDraft={updateDraft}
      moveRule={moveRule}
      duplicateRule={duplicateRule}
      deleteRule={deleteRule}
    />

    {!group.rules.length && <SourceGroupRulesEmptyState />}
  </div>
);
