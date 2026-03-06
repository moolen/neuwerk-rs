import React from 'react';
import { StringListMapEmptyState } from './StringListMapEmptyState';
import { StringListMapEntryRow } from './StringListMapEntryRow';
import {
  addStringListMapRow,
  removeStringListMapRow,
  renameStringListMapRow,
  updateStringListMapRow,
} from './stringListMapDraft';

interface StringListMapEditorProps {
  label: string;
  value: Record<string, string[]>;
  onChange: (next: Record<string, string[]>) => void;
  keyPlaceholder: string;
  valuePlaceholder: string;
}

export const StringListMapEditor: React.FC<StringListMapEditorProps> = ({
  label,
  value,
  onChange,
  keyPlaceholder,
  valuePlaceholder,
}) => {
  const entries = Object.entries(value);

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {label}
        </label>
        <button
          type="button"
          onClick={() => onChange(addStringListMapRow(value))}
          className="px-2 py-1 rounded text-xs"
          style={{
            background: 'var(--bg-glass-subtle)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
          }}
        >
          Add
        </button>
      </div>
      <div className="space-y-2">
        {entries.map(([entryKey, values], index) => (
          <StringListMapEntryRow
            key={`${entryKey}-${index}`}
            entryKey={entryKey}
            values={values ?? []}
            keyPlaceholder={keyPlaceholder}
            valuePlaceholder={valuePlaceholder}
            onChangeKey={(nextKey) =>
              onChange(renameStringListMapRow(value, entryKey, nextKey))
            }
            onChangeValues={(nextValuesRaw) =>
              onChange(updateStringListMapRow(value, entryKey, nextValuesRaw))
            }
            onRemove={() => onChange(removeStringListMapRow(value, entryKey))}
          />
        ))}
        {!entries.length && <StringListMapEmptyState />}
      </div>
    </div>
  );
};
