import React from 'react';

import type { PolicyTls13Uninspectable, PolicyTlsMode } from '../../../types';

interface RuleTlsModeControlsProps {
  mode: PolicyTlsMode;
  tls13Uninspectable: PolicyTls13Uninspectable;
  onModeChange: (mode: PolicyTlsMode) => void;
  onTls13UninspectableChange: (value: PolicyTls13Uninspectable) => void;
}

export const RuleTlsModeControls: React.FC<RuleTlsModeControlsProps> = ({
  mode,
  tls13Uninspectable,
  onModeChange,
  onTls13UninspectableChange,
}) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        TLS mode
      </label>
      <select
        value={mode}
        onChange={(e) => onModeChange(e.target.value as PolicyTlsMode)}
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <option value="metadata">metadata</option>
        <option value="intercept">intercept</option>
      </select>
    </div>
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        TLS 1.3 uninspectable
      </label>
      <select
        value={tls13Uninspectable}
        onChange={(e) => onTls13UninspectableChange(e.target.value as PolicyTls13Uninspectable)}
        className="w-full px-2 py-1 rounded text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <option value="deny">deny</option>
        <option value="allow">allow</option>
      </select>
    </div>
  </div>
);
