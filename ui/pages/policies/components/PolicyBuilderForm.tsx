import React from 'react';

import { PolicyBasicsSection } from './PolicyBasicsSection';
import type { PolicyBuilderFormSharedProps } from './formTypes';
import { SourceGroupsSection } from './SourceGroupsSection';

export const PolicyBuilderForm: React.FC<PolicyBuilderFormSharedProps> = ({
  draft,
  integrations,
  setDraft,
  updateDraft,
  addGroup,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => (
  <div className="p-4 space-y-6">
    <PolicyBasicsSection draft={draft} setDraft={setDraft} />
    <SourceGroupsSection
      draft={draft}
      integrations={integrations}
      setDraft={setDraft}
      updateDraft={updateDraft}
      addGroup={addGroup}
      duplicateGroup={duplicateGroup}
      moveGroup={moveGroup}
      deleteGroup={deleteGroup}
      addRule={addRule}
      duplicateRule={duplicateRule}
      moveRule={moveRule}
      deleteRule={deleteRule}
    />
  </div>
);
