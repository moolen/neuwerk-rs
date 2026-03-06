import React from 'react';

import type { PolicyTlsNameMatch } from '../../../types';
import { emptyTlsNameMatch, listToText, textToList } from '../helpers';

interface TlsNameMatchEditorProps {
  label: string;
  value?: PolicyTlsNameMatch;
  onChange: (next?: PolicyTlsNameMatch) => void;
}

export const TlsNameMatchEditor: React.FC<TlsNameMatchEditorProps> = ({ label, value, onChange }) => {
  const enabled = !!value;
  return (
    <div className="space-y-2 rounded p-3" style={{ border: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}>
      <div className="flex items-center justify-between">
        <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {label}
        </label>
        <button
          type="button"
          onClick={() => onChange(enabled ? undefined : emptyTlsNameMatch())}
          className="px-2 py-1 text-xs rounded"
          style={{
            background: 'var(--bg-glass-subtle)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
          }}
        >
          {enabled ? 'Disable' : 'Enable'}
        </button>
      </div>
      {enabled && value && (
        <>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
              Exact values (line or comma separated)
            </label>
            <textarea
              value={listToText(value.exact ?? [])}
              onChange={(e) => onChange({ ...value, exact: textToList(e.target.value) })}
              rows={2}
              className="w-full px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
              Regex
            </label>
            <input
              type="text"
              value={value.regex ?? ''}
              onChange={(e) => onChange({ ...value, regex: e.target.value })}
              className="w-full px-2 py-1 rounded text-sm"
              style={{ background: 'var(--bg)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
            />
          </div>
        </>
      )}
    </div>
  );
};
