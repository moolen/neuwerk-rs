import React from 'react';

import { TOKEN_TTL_PRESETS } from './createTokenForm';

interface CreateTokenModalFieldsProps {
  name: string;
  ttl: string;
  eternal: boolean;
  onNameChange: (next: string) => void;
  onTtlChange: (next: string) => void;
  onEternalChange: (next: boolean) => void;
}

export const CreateTokenModalFields: React.FC<CreateTokenModalFieldsProps> = ({
  name,
  ttl,
  eternal,
  onNameChange,
  onTtlChange,
  onEternalChange,
}) => (
  <>
    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        Name (optional)
      </label>
      <input
        value={name}
        onChange={(e) => onNameChange(e.target.value)}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="prod-reader"
      />
    </div>

    <div>
      <label className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
        TTL (optional)
      </label>
      <input
        value={ttl}
        onChange={(e) => onTtlChange(e.target.value)}
        className="w-full px-3 py-2 rounded-lg text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
        placeholder="90d or 24h"
        disabled={eternal}
      />
      <div className="mt-2 flex flex-wrap gap-2">
        {TOKEN_TTL_PRESETS.map((preset) => (
          <button
            key={preset}
            type="button"
            onClick={() => onTtlChange(preset)}
            disabled={eternal}
            className="px-2 py-1 text-xs rounded-lg"
            style={{
              background: 'var(--bg-input)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {preset}
          </button>
        ))}
      </div>
      <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
        If empty, default TTL applies.
      </p>
    </div>

    <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
      <input type="checkbox" checked={eternal} onChange={() => onEternalChange(!eternal)} />
      Eternal (no expiry)
    </label>
  </>
);
