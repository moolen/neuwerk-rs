import React from 'react';

import type { PolicyTls13Uninspectable, PolicyTlsMode } from '../../../types';
import { StyledSelect } from './StyledSelect';

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
  <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        TLS mode
      </label>
      <StyledSelect
        value={mode}
        onChange={(value) => onModeChange(value as PolicyTlsMode)}
        options={[
          { value: 'metadata', label: 'metadata' },
          { value: 'intercept', label: 'intercept' },
        ]}
      />
    </div>
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
        TLS 1.3 uninspectable
      </label>
      <StyledSelect
        value={tls13Uninspectable}
        onChange={(value) => onTls13UninspectableChange(value as PolicyTls13Uninspectable)}
        options={[
          { value: 'deny', label: 'deny' },
          { value: 'allow', label: 'allow' },
        ]}
      />
    </div>
  </div>
);
