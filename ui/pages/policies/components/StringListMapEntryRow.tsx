import React from 'react';
import { Trash2 } from 'lucide-react';

interface StringListMapEntryRowProps {
  entryKey: string;
  values: string[];
  keyPlaceholder: string;
  valuePlaceholder: string;
  onChangeKey: (nextKey: string) => void;
  onChangeValues: (nextValuesRaw: string) => void;
  onRemove: () => void;
}

export const StringListMapEntryRow: React.FC<StringListMapEntryRowProps> = ({
  entryKey,
  values,
  keyPlaceholder,
  valuePlaceholder,
  onChangeKey,
  onChangeValues,
  onRemove,
}) => (
  <div className="grid grid-cols-[1fr_1fr_auto] gap-2 items-start">
    <input
      type="text"
      value={entryKey}
      onChange={(e) => onChangeKey(e.target.value)}
      placeholder={keyPlaceholder}
      className="px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
    <input
      type="text"
      value={(values ?? []).join(', ')}
      onChange={(e) => onChangeValues(e.target.value)}
      placeholder={valuePlaceholder}
      className="px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        color: 'var(--text)',
      }}
    />
    <button
      type="button"
      onClick={onRemove}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Remove row"
    >
      <Trash2 className="w-4 h-4" />
    </button>
  </div>
);
