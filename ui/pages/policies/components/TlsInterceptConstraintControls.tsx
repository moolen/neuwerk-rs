import React from 'react';

interface TlsInterceptConstraintControlsProps {
  label: string;
  onEnable: () => void;
  onDisable: () => void;
}

const buttonStyle: React.CSSProperties = {
  background: 'var(--bg-input)',
  border: '1px solid var(--border-subtle)',
  color: 'var(--text-secondary)',
};

export const TlsInterceptConstraintControls: React.FC<TlsInterceptConstraintControlsProps> = ({
  label,
  onEnable,
  onDisable,
}) => (
  <div className="flex items-center gap-2">
    <button
      type="button"
      className="px-2 py-1 rounded text-xs"
      style={buttonStyle}
      onClick={onEnable}
    >
      Enable {label}
    </button>
    <button
      type="button"
      className="px-2 py-1 rounded text-xs"
      style={buttonStyle}
      onClick={onDisable}
    >
      Disable {label}
    </button>
  </div>
);
