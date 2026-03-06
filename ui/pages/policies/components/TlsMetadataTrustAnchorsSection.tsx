import React from 'react';

interface TlsMetadataTrustAnchorsSectionProps {
  trustAnchors: string[];
  onAdd: () => void;
  onChange: (index: number, value: string) => void;
  onRemove: (index: number) => void;
}

export const TlsMetadataTrustAnchorsSection: React.FC<TlsMetadataTrustAnchorsSectionProps> = ({
  trustAnchors,
  onAdd,
  onChange,
  onRemove,
}) => (
  <div className="space-y-2">
    <div className="flex items-center justify-between">
      <label className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Trust anchors (PEM)
      </label>
      <button
        type="button"
        onClick={onAdd}
        className="px-2 py-1 rounded text-xs"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        Add PEM
      </button>
    </div>
    {trustAnchors.map((pem, pemIndex) => (
      <div key={`pem-${pemIndex}`} className="space-y-1">
        <textarea
          value={pem}
          onChange={(e) => onChange(pemIndex, e.target.value)}
          rows={4}
          className="w-full px-2 py-1 rounded text-sm"
          style={{
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
        <button
          type="button"
          onClick={() => onRemove(pemIndex)}
          className="text-xs"
          style={{ color: 'var(--red)' }}
        >
          Remove PEM
        </button>
      </div>
    ))}
  </div>
);
