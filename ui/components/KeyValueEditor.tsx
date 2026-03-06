import React from 'react';
import { KeyValueEntriesList } from './key-value/KeyValueEntriesList';
import {
  addEmptyEntry,
  removeEntry as removeEntryFromMap,
  renameEntryKey,
  setEntryValue as setEntryValueInMap,
} from './key-value/state';
import { HEADER_SUGGESTIONS_LIST_ID } from './key-value/constants';
import { KeyValueEditorEmptyState } from './key-value/KeyValueEditorEmptyState';
import { KeyValueEditorHeader } from './key-value/KeyValueEditorHeader';
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
    onChange(renameEntryKey(data, oldKey, nextKey));
  };

  const setEntryValue = (key: string, nextValue: string) => {
    onChange(setEntryValueInMap(data, key, nextValue));
  };

  const addEntry = () => {
    onChange(addEmptyEntry(data));
  };

  const removeEntry = (key: string) => {
    onChange(removeEntryFromMap(data, key));
  };

  return (
    <div>
      <KeyValueEditorHeader label={label} disabled={disabled} onAddEntry={addEntry} />

      {entries.length === 0 && <KeyValueEditorEmptyState />}

      <KeyValueEntriesList
        fieldPrefix={fieldPrefix}
        entries={entries}
        keyPlaceholder={keyPlaceholder}
        valuePlaceholder={valuePlaceholder}
        disabled={disabled}
        errors={errors}
        onKeyChange={setEntryKey}
        onValueChange={setEntryValue}
        onRemove={removeEntry}
      />

      <datalist id={HEADER_SUGGESTIONS_LIST_ID}>
        {HEADER_SUGGESTIONS.map((header) => <option key={header} value={header} />)}
      </datalist>
    </div>
  );
};
