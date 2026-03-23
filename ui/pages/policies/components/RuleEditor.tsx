import React, { useState } from 'react';
import { ChevronDown, Copy, MoveDown, MoveUp, Trash2 } from 'lucide-react';

import { RuleHeaderFields } from './RuleHeaderFields';
import { RuleMatchCriteriaSection } from './RuleMatchCriteriaSection';
import { RuleTlsSection } from './RuleTlsSection';
import type { RuleEditorActionsProps, RuleEditorContextProps } from './ruleEditorTypes';
import { buildRuleSummary } from './ruleSummaryUtils';

type RuleEditorProps = RuleEditorContextProps & RuleEditorActionsProps;

export const RuleEditor: React.FC<RuleEditorProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
  moveRule,
  duplicateRule,
  deleteRule,
}) => {
  // Auto-expand rules that have no match criteria configured (i.e. newly added rules)
  const isNewRule =
    !rule.match.dst_cidrs?.length &&
    !rule.match.dst_ips?.length &&
    !rule.match.dns_hostname &&
    !rule.match.proto &&
    !rule.match.dst_ports?.length;

  const [isExpanded, setIsExpanded] = useState(isNewRule);
  const summary = buildRuleSummary(rule);
  const isAllow = rule.action === 'allow';
  const isAudit = rule.mode === 'audit';

  return (
    <div
      className="rounded-[1.15rem] overflow-hidden"
      style={{
        border: '1px solid var(--border-subtle)',
        background: 'var(--bg-glass-strong)',
      }}
    >
      {/* Summary row — always visible, click to expand */}
      <div
        className="flex items-center gap-2 px-3 py-2.5 cursor-pointer select-none"
        onClick={() => setIsExpanded((v) => !v)}
      >
        {/* Action chip */}
        <span
          className="px-2 py-0.5 rounded text-xs font-bold shrink-0"
          style={
            isAllow
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
          {rule.action.toUpperCase()}
        </span>

        {/* Mode chip — only shown when audit (enforce is the default/implied) */}
        {isAudit && (
          <span
            className="px-2 py-0.5 rounded text-xs font-medium shrink-0"
            style={{
              background: 'var(--amber-bg)',
              color: 'var(--amber)',
              border: '1px solid var(--amber-border)',
            }}
          >
            audit
          </span>
        )}

        {/* Match summary */}
        <span
          className="text-sm font-mono flex-1 min-w-0 truncate"
          style={{ color: 'var(--text-secondary)' }}
        >
          {summary}
        </span>

        {/* Rule identifier — secondary label, hidden on narrow viewports */}
        {rule.id && (
          <span
            className="text-xs shrink-0 hidden sm:inline-block"
            style={{ color: 'var(--text-muted)' }}
          >
            {rule.id}
          </span>
        )}

        {/* Action buttons — stop propagation so they don't toggle expand */}
        <div
          className="flex items-center gap-0.5 shrink-0"
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            onClick={() => moveRule(groupIndex, ruleIndex, -1)}
            className="p-1.5 rounded"
            style={{ color: 'var(--text-muted)' }}
            title="Move up"
          >
            <MoveUp className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => moveRule(groupIndex, ruleIndex, 1)}
            className="p-1.5 rounded"
            style={{ color: 'var(--text-muted)' }}
            title="Move down"
          >
            <MoveDown className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => duplicateRule(groupIndex, ruleIndex)}
            className="p-1.5 rounded"
            style={{ color: 'var(--text-muted)' }}
            title="Duplicate"
          >
            <Copy className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => deleteRule(groupIndex, ruleIndex)}
            className="p-1.5 rounded"
            style={{ color: 'var(--red)' }}
            title="Delete"
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

      {/* Expanded editor body */}
      {isExpanded && (
        <div
          className="p-4 space-y-5"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <section className="space-y-4">
            <div className="text-xs uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
              Rule settings
            </div>
            <RuleHeaderFields
              groupIndex={groupIndex}
              ruleIndex={ruleIndex}
              rule={rule}
              updateDraft={updateDraft}
            />
          </section>

          <section
            className="space-y-4 pt-4"
            style={{ borderTop: '1px solid var(--border-subtle)' }}
          >
            <div className="space-y-1">
              <h5 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                Match criteria
              </h5>
              <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
                Shape protocol, destination, port, and ICMP conditions for this rule.
              </p>
            </div>
            <RuleMatchCriteriaSection
              groupIndex={groupIndex}
              ruleIndex={ruleIndex}
              rule={rule}
              updateDraft={updateDraft}
            />
          </section>

          <section
            className="space-y-4 pt-4"
            style={{ borderTop: '1px solid var(--border-subtle)' }}
          >
            <div className="space-y-1">
              <h5 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
                TLS handling
              </h5>
              <p className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
                Configure metadata inspection or interception only when the match surface requires it.
              </p>
            </div>
            <RuleTlsSection
              groupIndex={groupIndex}
              ruleIndex={ruleIndex}
              rule={rule}
              updateDraft={updateDraft}
            />
          </section>
        </div>
      )}
    </div>
  );
};
