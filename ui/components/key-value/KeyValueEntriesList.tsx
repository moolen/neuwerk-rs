import React from 'react';
import { KeyValueEntryRow } from './KeyValueEntryRow';
import { displayKey } from './state';

interface KeyValueEntriesListProps {
  fieldPrefix: string;
  entries: Array<[string, string]>;
  keyPlaceholder: string;
  valuePlaceholder: string;
  disabled: boolean;
  errors: Record<string, string>;
  onKeyChange: (rawKey: string, nextKey: string) => void;
  onValueChange: (rawKey: string, nextValue: string) => void;
  onRemove: (rawKey: string) => void;
}

export const KeyValueEntriesList: React.FC<KeyValueEntriesListProps> = ({
  fieldPrefix,
  entries,
  keyPlaceholder,
  valuePlaceholder,
  disabled,
  errors,
  onKeyChange,
  onValueChange,
  onRemove,
}) => (
  <div className="space-y-2">
    {entries.map(([rawKey, rawValue], idx) => (
      <KeyValueEntryRow
        key={`${fieldPrefix}-${rawKey}-${idx}`}
        fieldPrefix={fieldPrefix}
        index={idx}
        displayKey={displayKey(rawKey)}
        rawValue={rawValue}
        keyPlaceholder={keyPlaceholder}
        valuePlaceholder={valuePlaceholder}
        disabled={disabled}
        errors={errors}
        onKeyChange={(nextKey) => onKeyChange(rawKey, nextKey)}
        onValueChange={(nextValue) => onValueChange(rawKey, nextValue)}
        onRemove={() => onRemove(rawKey)}
      />
    ))}
  </div>
);
