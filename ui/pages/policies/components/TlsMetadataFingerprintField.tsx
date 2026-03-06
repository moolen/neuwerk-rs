import React from 'react';

import { listToText, textToList } from '../helpers';

interface TlsMetadataFingerprintFieldProps {
  value: string[];
  onChange: (nextValue: string[]) => void;
}

export const TlsMetadataFingerprintField: React.FC<TlsMetadataFingerprintFieldProps> = ({
  value,
  onChange,
}) => (
  <div>
    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
      SHA256 fingerprints (line/comma separated)
    </label>
    <textarea
      value={listToText(value)}
      onChange={(e) => onChange(textToList(e.target.value))}
      rows={2}
      className="w-full px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
  </div>
);
