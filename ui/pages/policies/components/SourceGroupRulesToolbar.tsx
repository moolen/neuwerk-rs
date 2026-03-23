import React from 'react';

interface SourceGroupRulesToolbarProps {
  groupIndex: number;
  ruleCount: number;
  addRule: (groupIndex: number) => void;
}

export const SourceGroupRulesToolbar: React.FC<SourceGroupRulesToolbarProps> = ({
  groupIndex,
  ruleCount,
  addRule,
}) => (
  <div className="space-y-3">
    <div className="space-y-1">
      <div className="text-xs uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
        Configured rules
      </div>
      <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'} in evaluation order.
      </div>
    </div>
    <button
      type="button"
      onClick={() => addRule(groupIndex)}
      className="px-3 py-2 rounded-xl text-xs font-medium self-start"
      style={{
        background: 'var(--bg-glass-subtle)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    >
      Add Rule
    </button>
  </div>
);
