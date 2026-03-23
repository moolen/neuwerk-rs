import React from 'react';

import { RuleHeaderSection } from './RuleHeaderSection';
import { RuleMatchCriteriaSection } from './RuleMatchCriteriaSection';
import { RuleTlsSection } from './RuleTlsSection';
import type { RuleEditorActionsProps, RuleEditorContextProps } from './ruleEditorTypes';

type RuleEditorProps = RuleEditorContextProps & RuleEditorActionsProps;

function sectionStyle(): React.CSSProperties {
  return {
    border: '1px solid var(--border-glass)',
    background: 'rgba(255,255,255,0.04)',
  };
}

export const RuleEditor: React.FC<RuleEditorProps> = ({
  groupIndex,
  ruleIndex,
  rule,
  updateDraft,
  moveRule,
  duplicateRule,
  deleteRule,
}) => (
  <div
    className="rounded-[1.15rem] p-4 space-y-4"
    style={{
      border: '1px solid var(--border-subtle)',
      background: 'var(--bg-glass-strong)',
    }}
  >
    <section className="rounded-[1rem] p-4 space-y-4" style={sectionStyle()}>
      <div className="space-y-1">
        <div className="text-xs uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Rule {ruleIndex + 1}
        </div>
        <div className="text-sm leading-6" style={{ color: 'var(--text-secondary)' }}>
          Set ordering, decision, and execution mode before narrowing the match surface.
        </div>
      </div>

      <RuleHeaderSection
        groupIndex={groupIndex}
        ruleIndex={ruleIndex}
        rule={rule}
        updateDraft={updateDraft}
        moveRule={moveRule}
        duplicateRule={duplicateRule}
        deleteRule={deleteRule}
      />
    </section>

    <div className="grid gap-4 2xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.9fr)] 2xl:items-start">
      <section className="rounded-[1rem] p-4 space-y-4" style={sectionStyle()}>
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

      <section className="rounded-[1rem] p-4 space-y-4" style={sectionStyle()}>
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
  </div>
);
