import React from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { HEADER_SUGGESTIONS } from '../utils/validation';

interface KeyValueEditorProps {
  label: string;
  value?: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
  disabled?: boolean;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
  fieldPrefix: string;
  errors: Record<string, string>;
}

function newTempKey() {
  return `__tmp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export const KeyValueEditor: React.FC<KeyValueEditorProps> = ({
  label,
  value,
  onChange,
  disabled = false,
  keyPlaceholder = 'Header name',
  valuePlaceholder = 'Regex',
  fieldPrefix,
  errors,
}) => {
  const data: Record<string, string> = value ? { ...value } : {};
  const entries = Object.entries(data);

  const setEntryKey = (oldKey: string, nextKey: string) => {
    const next: Record<string, string> = {};
    for (const [k, v] of entries) {
      if (k !== oldKey) {
        next[k] = v;
      }
    }
    next[nextKey.trim() || newTempKey()] = data[oldKey] ?? '';
    onChange(next);
  };

  const setEntryValue = (key: string, nextValue: string) => {
    onChange({
      ...data,
      [key]: nextValue,
    });
  };

  const addEntry = () => {
    onChange({
      ...data,
      [newTempKey()]: '',
    });
  };

  const removeEntry = (key: string) => {
    const next = { ...data };
    delete next[key];
    onChange(next);
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>{label}</label>
        <button
          type="button"
          onClick={addEntry}
          disabled={disabled}
          className="px-2 py-1 rounded text-xs flex items-center gap-1"
          style={{ background: 'var(--bg-glass-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}
        >
          <Plus className="w-3 h-3" /> Add
        </button>
      </div>

      {entries.length === 0 && (
        <div className="text-xs py-2 px-2 rounded" style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}>
          No entries configured.
        </div>
      )}

      <div className="space-y-2">
        {entries.map(([rawKey, rawValue], idx) => {
          const displayKey = rawKey.startsWith('__tmp_') ? '' : rawKey;
          return (
            <div key={`${fieldPrefix}-${rawKey}-${idx}`} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-start">
              <div>
                <input
                  type="text"
                  value={displayKey}
                  onChange={(e) => setEntryKey(rawKey, e.target.value)}
                  disabled={disabled}
                  placeholder={keyPlaceholder}
                  list="header-suggestions"
                  className="w-full px-2 py-1 rounded text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: `1px solid ${errors[`${fieldPrefix}.${idx}.key`] ? 'var(--red)' : 'var(--border-subtle)'}`,
                    color: 'var(--text)',
                  }}
                />
                {errors[`${fieldPrefix}.${idx}.key`] && (
                  <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>{errors[`${fieldPrefix}.${idx}.key`]}</p>
                )}
              </div>

              <div>
                <input
                  type="text"
                  value={rawValue}
                  onChange={(e) => setEntryValue(rawKey, e.target.value)}
                  disabled={disabled}
                  placeholder={valuePlaceholder}
                  className="w-full px-2 py-1 rounded text-sm"
                  style={{
                    background: 'var(--bg-input)',
                    border: `1px solid ${errors[`${fieldPrefix}.${idx}.value`] ? 'var(--red)' : 'var(--border-subtle)'}`,
                    color: 'var(--text)',
                  }}
                />
                {errors[`${fieldPrefix}.${idx}.value`] && (
                  <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>{errors[`${fieldPrefix}.${idx}.value`]}</p>
                )}
              </div>

              <button
                type="button"
                onClick={() => removeEntry(rawKey)}
                disabled={disabled}
                className="p-2 rounded"
                style={{ color: 'var(--text-muted)' }}
                title="Remove entry"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          );
        })}
      </div>

      <datalist id="header-suggestions">
        {HEADER_SUGGESTIONS.map((header) => <option key={header} value={header} />)}
      </datalist>
    </div>
  );
};
