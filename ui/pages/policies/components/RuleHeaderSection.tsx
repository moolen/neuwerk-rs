import React from 'react';

import type { RuleEditorActionsProps, RuleEditorContextProps } from './ruleEditorTypes';
import { RuleHeaderActions } from './RuleHeaderActions';
import { RuleHeaderFields } from './RuleHeaderFields';

type RuleHeaderSectionProps = RuleEditorContextProps & RuleEditorActionsProps;

export const RuleHeaderSection: React.FC<RuleHeaderSectionProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
  moveRule,
  duplicateRule,
  deleteRule,
}) => (
  <div className="flex flex-col gap-3">
    <RuleHeaderFields
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      rule={rule}
      updateDraft={updateDraft}
    />
    <RuleHeaderActions
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      moveRule={moveRule}
      duplicateRule={duplicateRule}
      deleteRule={deleteRule}
    />
  </div>
);
