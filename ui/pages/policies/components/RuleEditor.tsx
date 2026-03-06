import React from 'react';

import { RuleHeaderSection } from './RuleHeaderSection';
import { RuleMatchCriteriaSection } from './RuleMatchCriteriaSection';
import { RuleTlsSection } from './RuleTlsSection';
import type { RuleEditorActionsProps, RuleEditorContextProps } from './ruleEditorTypes';

type RuleEditorProps = RuleEditorContextProps & RuleEditorActionsProps;

export const RuleEditor: React.FC<RuleEditorProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
  moveRule,
  duplicateRule,
  deleteRule,
}) => (
  <div className="rounded p-3 space-y-3" style={{ border: '1px dashed var(--border-subtle)' }}>
    <RuleHeaderSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      rule={rule}
      updateDraft={updateDraft}
      moveRule={moveRule}
      duplicateRule={duplicateRule}
      deleteRule={deleteRule}
    />
    <RuleMatchCriteriaSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      rule={rule}
      updateDraft={updateDraft}
    />
    <RuleTlsSection
      groupIndex={groupIndex}
      ruleIndex={ruleIndex}
      rule={rule}
      updateDraft={updateDraft}
    />
  </div>
);
