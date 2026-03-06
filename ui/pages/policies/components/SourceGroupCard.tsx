import React from 'react';

import { SourceGroupHeaderSection } from './SourceGroupHeaderSection';
import { SourceGroupRulesSection } from './SourceGroupRulesSection';
import { SourceGroupSourcesSection } from './SourceGroupSourcesSection';
import type {
  SourceGroupActionProps,
  SourceGroupContextProps,
} from './sourceGroupTypes';

type SourceGroupCardProps = SourceGroupContextProps & SourceGroupActionProps;

export const SourceGroupCard: React.FC<SourceGroupCardProps> = ({
  group,
  groupIndex,
  integrations,
  updateDraft,
  duplicateGroup,
  moveGroup,
  deleteGroup,
  addRule,
  duplicateRule,
  moveRule,
  deleteRule,
}) => (
  <div
    className="rounded-lg p-4 space-y-4"
    style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}
  >
    <SourceGroupHeaderSection
      group={group}
      groupIndex={groupIndex}
      updateDraft={updateDraft}
      duplicateGroup={duplicateGroup}
      moveGroup={moveGroup}
      deleteGroup={deleteGroup}
    />
    <SourceGroupSourcesSection
      group={group}
      groupIndex={groupIndex}
      integrations={integrations}
      updateDraft={updateDraft}
    />
    <SourceGroupRulesSection
      group={group}
      groupIndex={groupIndex}
      updateDraft={updateDraft}
      addRule={addRule}
      duplicateRule={duplicateRule}
      moveRule={moveRule}
      deleteRule={deleteRule}
    />
  </div>
);
