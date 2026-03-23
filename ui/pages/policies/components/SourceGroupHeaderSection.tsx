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
  <div className="space-y-4">
    <div className="flex flex-col gap-3">
      <div className="space-y-1">
        <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
          Source group {groupIndex + 1}
        </div>
        <div className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Tune the group identity, evaluation order, and fallback before editing nested source selectors and rules.
        </div>
      </div>

      <SourceGroupHeaderActions
        groupIndex={groupIndex}
        duplicateGroup={duplicateGroup}
        moveGroup={moveGroup}
        deleteGroup={deleteGroup}
      />
    </div>

    <SourceGroupHeaderFields group={group} groupIndex={groupIndex} updateDraft={updateDraft} />
  </div>
);
