import React from 'react';

import type { SourceGroupActionProps, SourceGroupContextProps } from './sourceGroupTypes';
import { SourceGroupHeaderActions } from './SourceGroupHeaderActions';
import { SourceGroupHeaderFields } from './SourceGroupHeaderFields';

type SourceGroupHeaderSectionProps = Pick<
  SourceGroupActionProps,
  'duplicateGroup' | 'moveGroup' | 'deleteGroup'
> &
  Pick<SourceGroupContextProps, 'group' | 'groupIndex' | 'updateDraft'>;

export const SourceGroupHeaderSection: React.FC<SourceGroupHeaderSectionProps> = ({
  group,
  groupIndex,
  updateDraft,
  duplicateGroup,
  moveGroup,
  deleteGroup,
}) => (
  <div className="flex items-start justify-between gap-4">
    <SourceGroupHeaderFields group={group} groupIndex={groupIndex} updateDraft={updateDraft} />
    <SourceGroupHeaderActions
      groupIndex={groupIndex}
      duplicateGroup={duplicateGroup}
      moveGroup={moveGroup}
      deleteGroup={deleteGroup}
    />
  </div>
);
