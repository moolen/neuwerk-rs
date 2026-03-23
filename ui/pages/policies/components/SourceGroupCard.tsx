import React from 'react';

import { SourceGroupHeaderSection } from './SourceGroupHeaderSection';
import { SourceGroupRulesSection } from './SourceGroupRulesSection';
import { SourceGroupSourcesSection } from './SourceGroupSourcesSection';
import type {
  SourceGroupActionProps,
  SourceGroupContextProps,
} from './sourceGroupTypes';

type SourceGroupCardProps = SourceGroupContextProps & SourceGroupActionProps;

function cardStyle(): React.CSSProperties {
  return {
    border: '1px solid var(--border-glass)',
    background: 'linear-gradient(180deg, var(--bg-glass-strong), rgba(255,255,255,0.04))',
    boxShadow: 'var(--shadow-glass)',
  };
}

function sectionStyle(): React.CSSProperties {
  return {
    border: '1px solid var(--border-glass)',
    background: 'rgba(255,255,255,0.035)',
  };
}

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
    className="rounded-[1.35rem] p-4 space-y-4"
    style={cardStyle()}
  >
    <section className="rounded-[1.1rem] p-4" style={sectionStyle()}>
      <SourceGroupHeaderSection
        group={group}
        groupIndex={groupIndex}
        updateDraft={updateDraft}
        duplicateGroup={duplicateGroup}
        moveGroup={moveGroup}
        deleteGroup={deleteGroup}
      />
    </section>

    <div className="grid gap-4 2xl:grid-cols-[minmax(0,1.15fr)_minmax(19rem,0.95fr)] 2xl:items-start">
      <section className="rounded-[1.1rem] p-4 space-y-4" style={sectionStyle()}>
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

      <section className="rounded-[1.1rem] p-4 space-y-4" style={sectionStyle()}>
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
  </div>
);
