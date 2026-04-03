import React, { useState } from 'react';
import { ChevronDown, Copy, MoveDown, MoveUp, Trash2 } from 'lucide-react';

import { SourceGroupHeaderFields } from './SourceGroupHeaderFields';
import { SourceGroupRulesSection } from './SourceGroupRulesSection';
import { SourceGroupSourcesSection } from './SourceGroupSourcesSection';
import type { SourceGroupActionProps, SourceGroupContextProps } from './sourceGroupTypes';

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
}) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const sourceCount =
    (group.sources.cidrs?.length ?? 0) +
    (group.sources.ips?.length ?? 0) +
    (group.sources.kubernetes?.length ?? 0);
  const ruleCount = group.rules.length;
  const fallbackAction = group.default_action ?? 'deny';
  const displayName = group.id || `Group ${groupIndex + 1}`;

  return (
    <div
      className="rounded-[1.35rem] overflow-hidden"
      style={{ border: '1px solid var(--border-subtle)' }}
    >
      {/* Summary header row */}
      <div
        className="flex cursor-pointer select-none flex-col gap-3 px-4 py-3 sm:flex-row sm:items-start"
        onClick={() => setIsExpanded((v) => !v)}
      >
        <div className="min-w-0 flex-1 space-y-2">
          {/* Group name */}
          <span
            className="block min-w-0 text-sm font-semibold truncate"
            style={{ color: 'var(--text)' }}
          >
            {displayName}
          </span>

          <div className="flex flex-wrap gap-2">
            {/* Source count badge */}
            {sourceCount > 0 && (
              <span
                className="px-2 py-0.5 rounded text-xs shrink-0"
                style={{
                  background: 'var(--accent-soft)',
                  color: 'var(--accent)',
                  border: '1px solid rgba(79,110,247,0.2)',
                }}
              >
                {sourceCount} {sourceCount === 1 ? 'source' : 'sources'}
              </span>
            )}

            {/* Rule count badge */}
            <span
              className="px-2 py-0.5 rounded text-xs shrink-0"
              style={{
                background: 'var(--bg-glass-subtle)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'}
            </span>

            {/* Fallback action chip */}
            <span
              className="px-2 py-0.5 rounded text-xs font-medium shrink-0"
              style={
                fallbackAction === 'allow'
                  ? {
                      background: 'var(--green-bg)',
                      color: 'var(--green)',
                      border: '1px solid var(--green-border)',
                    }
                  : {
                      background: 'var(--red-bg)',
                      color: 'var(--red)',
                      border: '1px solid var(--red-border)',
                    }
              }
            >
              fallback: {fallbackAction}
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between gap-2 sm:shrink-0">
          {/* Action buttons */}
          <div
            className="flex items-center gap-0.5 shrink-0"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => moveGroup(groupIndex, -1)}
              className="p-1.5 rounded"
              style={{ color: 'var(--text-muted)' }}
              title="Move up"
            >
              <MoveUp className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => moveGroup(groupIndex, 1)}
              className="p-1.5 rounded"
              style={{ color: 'var(--text-muted)' }}
              title="Move down"
            >
              <MoveDown className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => duplicateGroup(groupIndex)}
              className="p-1.5 rounded"
              style={{ color: 'var(--text-muted)' }}
              title="Duplicate group"
            >
              <Copy className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => deleteGroup(groupIndex)}
              className="p-1.5 rounded"
              style={{ color: 'var(--red)' }}
              title="Delete group"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Expand chevron */}
          <ChevronDown
            className="w-4 h-4 shrink-0"
            style={{
              color: 'var(--text-muted)',
              transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
              transition: 'transform 150ms ease',
            }}
          />
        </div>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div
          className="px-4 pb-4 pt-4 space-y-5"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <div className="grid gap-6 xl:grid-cols-[minmax(15rem,0.9fr)_minmax(0,1.1fr)] xl:items-start">
            <section className="space-y-4">
              <SourceGroupHeaderFields
                group={group}
                groupIndex={groupIndex}
                updateDraft={updateDraft}
              />
            </section>

            <section className="space-y-4">
              <div className="space-y-1">
                <h4 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                  Source selectors
                </h4>
                <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
                  Define the networks, IPs, and Kubernetes workloads that enter this policy branch.
                </p>
              </div>
              <SourceGroupSourcesSection
                group={group}
                groupIndex={groupIndex}
                integrations={integrations}
                updateDraft={updateDraft}
              />
            </section>
          </div>

          <section
            className="space-y-4 pt-4"
            style={{ borderTop: '1px solid var(--border-subtle)' }}
          >
            <div className="space-y-1">
              <h4 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                Rule stack
              </h4>
              <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
                Order the allow and deny rules that apply after the group-level source scope matches.
              </p>
            </div>
            <SourceGroupRulesSection
              group={group}
              groupIndex={groupIndex}
              updateDraft={updateDraft}
              addRule={addRule}
              duplicateRule={duplicateRule}
              moveRule={moveRule}
              deleteRule={deleteRule}
            />
          </section>
        </div>
      )}
    </div>
  );
};
