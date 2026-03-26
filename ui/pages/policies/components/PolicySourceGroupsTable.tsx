import React from 'react';
import { Plus } from 'lucide-react';

import type { PolicySourceGroup, PolicySourceGroupTelemetry } from '../../../types';
import { PolicySourceGroupRow } from './PolicySourceGroupRow';

interface PolicySourceGroupsTableProps {
  groups: PolicySourceGroup[];
  activeSourceGroupId: string | null;
  telemetryBySourceGroupId?: Record<string, PolicySourceGroupTelemetry>;
  telemetryPartial?: boolean;
  telemetryNodesQueried?: number;
  telemetryNodesResponded?: number;
  telemetryNodeErrorCount?: number;
  createActionLabel?: string;
  emptyStateDescription?: string;
  emptyStateTitle?: string;
  onCreateGroup: () => void;
  onDeleteGroup: (groupId: string) => void;
  onMoveGroup: (groupId: string, direction: -1 | 1) => void;
  onSelectGroup: (groupId: string) => void;
}

export const PolicySourceGroupsTable: React.FC<PolicySourceGroupsTableProps> = ({
  groups,
  activeSourceGroupId,
  telemetryBySourceGroupId = {},
  telemetryPartial = false,
  telemetryNodesQueried = 0,
  telemetryNodesResponded = 0,
  telemetryNodeErrorCount = 0,
  createActionLabel = 'Add source group',
  emptyStateDescription = 'Create the first source group to start shaping the selected policy.',
  emptyStateTitle = 'No source groups configured',
  onCreateGroup,
  onDeleteGroup,
  onMoveGroup,
  onSelectGroup,
}) => (
  <section
    className="rounded-[1.5rem] overflow-hidden"
    style={{
      background: 'linear-gradient(180deg, var(--bg-glass-strong), rgba(255,255,255,0.04))',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex flex-col gap-4 px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="space-y-1.5">
        <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
          Source groups
        </div>
        <h2 className="text-base font-semibold" style={{ color: 'var(--text)' }}>
          Source Identity
        </h2>
        <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Click any row to open an in-page source-group editor while keeping the list visible underneath.
        </p>
      </div>

      <button
        type="button"
        onClick={onCreateGroup}
        className="inline-flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <Plus className="h-4 w-4" />
        {createActionLabel}
      </button>
    </div>

    {telemetryPartial ? (
      <div
        className="mx-4 mb-4 rounded-[1rem] px-4 py-3 text-sm"
        style={{
          background: 'var(--amber-bg, color-mix(in srgb, var(--bg-glass-subtle) 60%, #f59e0b 16%))',
          border: '1px solid var(--amber-border, color-mix(in srgb, var(--border-subtle) 55%, #f59e0b 30%))',
          color: 'var(--text)',
        }}
      >
        <div className="font-semibold">Telemetry is partial</div>
        <div className="mt-1" style={{ color: 'var(--text-secondary)' }}>
          {telemetryNodesResponded} of {telemetryNodesQueried} nodes responded.{' '}
          {telemetryNodeErrorCount} node error{telemetryNodeErrorCount === 1 ? '' : 's'}.
        </div>
      </div>
    ) : null}

    {groups.length ? (
      <>
        <div
          className="hidden gap-3 px-4 py-3 text-xs uppercase tracking-[0.22em] lg:grid lg:grid-cols-[minmax(0,1.65fr)_minmax(0,1.45fr)_8rem_10rem_8rem]"
          style={{
            color: 'var(--text-muted)',
            borderTop: '1px solid var(--border-glass)',
            borderBottom: '1px solid var(--border-glass)',
            background: 'rgba(255,255,255,0.025)',
          }}
        >
          <div>Source Identity</div>
          <div>L3/L4/DNS/DPI Rules</div>
          <div>Action</div>
          <div>Hits</div>
          <div className="text-right">Manage</div>
        </div>

        <div>
          {groups.map((group, groupIndex) => (
            <PolicySourceGroupRow
              key={`${group.id}-${groupIndex}`}
              group={group}
              groupIndex={groupIndex}
              isActive={activeSourceGroupId === group.id}
              telemetry={telemetryBySourceGroupId[group.id]}
              onDeleteGroup={onDeleteGroup}
              onMoveGroup={onMoveGroup}
              onSelectGroup={onSelectGroup}
            />
          ))}
        </div>
      </>
    ) : (
      <div
        className="mx-4 mb-4 rounded-[1.2rem] border border-dashed px-4 py-8 text-center"
        style={{
          borderColor: 'var(--border-subtle)',
          background: 'var(--bg-glass-subtle)',
        }}
      >
        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
          {emptyStateTitle}
        </div>
        <p className="mt-2 text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          {emptyStateDescription}
        </p>
        <button
          type="button"
          onClick={onCreateGroup}
          className="mt-4 inline-flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium"
          style={{
            background: 'var(--accent-light)',
            border: '1px solid rgba(79,110,247,0.2)',
            color: 'var(--accent)',
          }}
        >
          <Plus className="h-4 w-4" />
          {createActionLabel === 'Add source group' ? 'Add first source group' : createActionLabel}
        </button>
      </div>
    )}
  </section>
);
