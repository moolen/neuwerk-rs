import React from 'react';

interface RuleTlsHeaderProps {
  enabled: boolean;
  onToggle: () => void;
}

export const RuleTlsHeader: React.FC<RuleTlsHeaderProps> = ({ enabled, onToggle }) => (
  <div className="flex items-center justify-between">
    <h5 className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
      TLS Constraints
    </h5>
    <button
      type="button"
      onClick={onToggle}
      className="px-2 py-1 rounded text-xs"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text-secondary)',
      }}
    >
      {enabled ? 'Disable TLS' : 'Enable TLS'}
    </button>
  </div>
);
