import React, { useState } from 'react';
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Minus,
  MoreHorizontal,
  MoveDown,
  MoveUp,
  PencilLine,
  Trash2,
} from 'lucide-react';

import type { PolicySourceGroup, PolicySourceGroupTelemetry } from '../../../types';
import { formatHitsTrend } from './policyTelemetryHelpers';
import {
  summarizeGroupAction,
  summarizeRulePills,
  summarizeSourceIdentity,
} from './policySourceGroupTableHelpers';

interface PolicySourceGroupRowProps {
  group: PolicySourceGroup;
  groupIndex: number;
  isActive: boolean;
  telemetry?: PolicySourceGroupTelemetry;
  onDeleteGroup: (groupId: string) => void;
  onMoveGroup: (groupId: string, direction: -1 | 1) => void;
  onSelectGroup: (groupId: string) => void;
}

function actionPillStyle(action: ReturnType<typeof summarizeGroupAction>): React.CSSProperties {
  if (action === 'allow') {
    return {
      background: 'var(--green-bg)',
      border: '1px solid var(--green-border)',
      color: 'var(--green)',
    };
  }

  if (action === 'deny') {
    return {
      background: 'var(--red-bg)',
      border: '1px solid var(--red-border)',
      color: 'var(--red)',
    };
  }

  return {
    background: 'var(--bg-glass-subtle)',
    border: '1px solid var(--border-subtle)',
    color: 'var(--text-secondary)',
  };
}

function modePillStyle(mode: PolicySourceGroup['mode']): React.CSSProperties {
  if (mode === 'audit') {
    return {
      background: 'var(--amber-bg)',
      border: '1px solid var(--amber-border)',
      color: 'var(--amber)',
    };
  }

  return {
    background: 'var(--accent-light)',
    border: '1px solid rgba(79,110,247,0.3)',
    color: 'var(--accent)',
  };
}

export const PolicySourceGroupRow: React.FC<PolicySourceGroupRowProps> = ({
  group,
  groupIndex,
  isActive,
  telemetry,
  onDeleteGroup,
  onMoveGroup,
  onSelectGroup,
}) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const groupKey = group.client_key ?? group.id;
  const identity = summarizeSourceIdentity(group);
  const rulePills = summarizeRulePills(group);
  const action = summarizeGroupAction(group);
  const mode = group.mode ?? 'enforce';
  const hitsTrend = formatHitsTrend(telemetry);

  let trendIcon = <Minus className="h-3 w-3" />;
  let trendStyle: React.CSSProperties = {
    background: 'var(--bg-glass-subtle)',
    border: '1px solid var(--border-subtle)',
    color: 'var(--text-muted)',
  };
  if (hitsTrend.direction === 'up') {
    trendIcon = <ArrowUpRight className="h-3 w-3" />;
    trendStyle = {
      background: 'var(--green-bg)',
      border: '1px solid var(--green-border)',
      color: 'var(--green)',
    };
  } else if (hitsTrend.direction === 'down') {
    trendIcon = <ArrowDownRight className="h-3 w-3" />;
    trendStyle = {
      background: 'var(--red-bg)',
      border: '1px solid var(--red-border)',
      color: 'var(--red)',
    };
  } else if (hitsTrend.direction === 'flat') {
    trendIcon = <ArrowRight className="h-3 w-3" />;
  }

  return (
    <div
      className="grid gap-3 px-4 py-4 lg:grid-cols-[minmax(0,1.65fr)_minmax(0,1.45fr)_8rem_10rem_8rem] lg:items-center"
      onClick={() => onSelectGroup(groupKey)}
      style={{
        cursor: 'pointer',
        background: isActive
          ? 'linear-gradient(145deg, rgba(79,110,247,0.14), rgba(79,110,247,0.05))'
          : 'transparent',
        borderTop: groupIndex === 0 ? 'none' : '1px solid var(--border-glass)',
      }}
    >
      <div className="min-w-0 space-y-1">
        <div className="text-sm font-semibold truncate" style={{ color: 'var(--text)' }}>
          {identity.primary}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {identity.secondary.length ? (
            identity.secondary.map((value) => (
              <span
                key={value}
                className="rounded-full px-2 py-0.5 text-xs"
                style={{
                  background: 'var(--bg-glass-subtle)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-muted)',
                }}
              >
                {value}
              </span>
            ))
          ) : (
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              No CIDRs or IPs configured
            </span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {rulePills.length ? (
          rulePills.map((pill) => (
            <span
              key={pill}
              className="rounded-full px-2.5 py-1 text-xs"
              style={{
                background: 'var(--bg-glass-subtle)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              {pill}
            </span>
          ))
        ) : (
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            No rules configured
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span
          className="inline-flex rounded-full px-2.5 py-1 text-xs font-semibold"
          style={actionPillStyle(action)}
        >
          {action.charAt(0).toUpperCase() + action.slice(1)}
        </span>
        <span
          className="inline-flex rounded-full px-2.5 py-1 text-xs font-medium"
          style={modePillStyle(mode)}
        >
          {mode === 'audit' ? 'Audit' : 'Enforce'}
        </span>
      </div>

      <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
        <span className="font-medium" style={{ color: 'var(--text)' }}>
          {hitsTrend.totalLabel}
        </span>
        <span
          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs"
          style={trendStyle}
        >
          {trendIcon}
          {hitsTrend.trendLabel}
        </span>
      </div>

      <div className="flex items-center justify-between gap-2 lg:justify-end">
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onMoveGroup(groupKey, -1);
            }}
            className="rounded-lg p-2"
            style={{ color: 'var(--text-muted)' }}
            title="Move up"
          >
            <MoveUp className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onMoveGroup(groupKey, 1);
            }}
            className="rounded-lg p-2"
            style={{ color: 'var(--text-muted)' }}
            title="Move down"
          >
            <MoveDown className="h-4 w-4" />
          </button>
        </div>

        <div className="relative">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              setMenuOpen((open) => !open);
            }}
            className="rounded-lg p-2"
            style={{ color: 'var(--text-muted)' }}
            title="More actions"
          >
            <MoreHorizontal className="h-4 w-4" />
          </button>

          {menuOpen ? (
            <div
              className="absolute right-0 top-[calc(100%+0.35rem)] z-10 min-w-40 rounded-[1rem] p-1"
              style={{
                background: 'color-mix(in srgb, var(--bg-glass-strong) 88%, var(--bg) 12%)',
                border: '1px solid var(--border-glass)',
                boxShadow: 'var(--shadow-glass)',
              }}
            >
              <button
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  setMenuOpen(false);
                  onSelectGroup(groupKey);
                }}
                className="flex w-full items-center gap-2 rounded-[0.8rem] px-3 py-2 text-sm"
                style={{ color: 'var(--text)' }}
              >
                <PencilLine className="h-4 w-4" />
                Edit
              </button>
              <button
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  setMenuOpen(false);
                  onDeleteGroup(groupKey);
                }}
                className="flex w-full items-center gap-2 rounded-[0.8rem] px-3 py-2 text-sm"
                style={{ color: 'var(--red)' }}
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
