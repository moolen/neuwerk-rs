import React from 'react';

import type { PolicySourceGroup } from '../../../types';
import { RuleEditor } from './RuleEditor';
import type { UpdateDraft } from './formTypes';

interface SourceGroupRulesListProps {
  group: PolicySourceGroup;
  groupIndex: number;
  updateDraft: UpdateDraft;
  duplicateRule: (groupIndex: number, ruleIndex: number) => void;
  moveRule: (groupIndex: number, ruleIndex: number, direction: -1 | 1) => void;
  deleteRule: (groupIndex: number, ruleIndex: number) => void;
}

export const SourceGroupRulesList: React.FC<SourceGroupRulesListProps> = ({
  group,
  groupIndex,
  updateDraft,
  duplicateRule,
  moveRule,
  deleteRule,
}) => (
  <>
    {group.rules.map((rule, ruleIndex) => (
      <RuleEditor
        key={ruleIndex}
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        rule={rule}
        updateDraft={updateDraft}
        moveRule={moveRule}
        duplicateRule={duplicateRule}
        deleteRule={deleteRule}
      />
    ))}
  </>
);
