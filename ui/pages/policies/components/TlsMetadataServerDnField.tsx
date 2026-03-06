import React from 'react';

interface TlsMetadataServerDnFieldProps {
  value: string;
  onChange: (value: string) => void;
}

export const TlsMetadataServerDnField: React.FC<TlsMetadataServerDnFieldProps> = ({
  value,
  onChange,
}) => (
  <div>
    <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
      Legacy server_dn regex
    </label>
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
  </div>
);
