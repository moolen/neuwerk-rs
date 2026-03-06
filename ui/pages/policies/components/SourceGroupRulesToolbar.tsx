import React from 'react';

interface SourceGroupRulesToolbarProps {
  groupIndex: number;
  addRule: (groupIndex: number) => void;
}

export const SourceGroupRulesToolbar: React.FC<SourceGroupRulesToolbarProps> = ({
  groupIndex,
  addRule,
}) => (
  <div className="flex items-center justify-between">
    <h4 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
      Rules
    </h4>
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={() => addRule(groupIndex)}
        className="px-2 py-1 rounded text-xs"
        style={{
          background: 'var(--bg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        Add Rule
      </button>
    </div>
  </div>
);
