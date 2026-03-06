import React from 'react';
import { Trash2 } from 'lucide-react';
import { HEADER_SUGGESTIONS_LIST_ID } from './constants';
import { entryFieldError } from './fieldErrors';
import { KeyValueEntryInput } from './KeyValueEntryInput';

interface KeyValueEntryRowProps {
  fieldPrefix: string;
  index: number;
  displayKey: string;
  rawValue: string;
  keyPlaceholder: string;
  valuePlaceholder: string;
  disabled: boolean;
  errors: Record<string, string>;
  onKeyChange: (nextKey: string) => void;
  onValueChange: (nextValue: string) => void;
  onRemove: () => void;
}

export const KeyValueEntryRow: React.FC<KeyValueEntryRowProps> = ({
  fieldPrefix,
  index,
  displayKey,
  rawValue,
  keyPlaceholder,
  valuePlaceholder,
  disabled,
  errors,
  onKeyChange,
  onValueChange,
  onRemove,
}) => (
  <div className="grid grid-cols-[1fr_1fr_auto] gap-2 items-start">
    <div>
      <KeyValueEntryInput
        value={displayKey}
        onChange={onKeyChange}
        disabled={disabled}
        placeholder={keyPlaceholder}
        listId={HEADER_SUGGESTIONS_LIST_ID}
        error={entryFieldError(errors, fieldPrefix, index, 'key')}
      />
    </div>

    <div>
      <KeyValueEntryInput
        value={rawValue}
        onChange={onValueChange}
        disabled={disabled}
        placeholder={valuePlaceholder}
        error={entryFieldError(errors, fieldPrefix, index, 'value')}
      />
    </div>

    <button
      type="button"
      onClick={onRemove}
      disabled={disabled}
      className="p-2 rounded"
      style={{ color: 'var(--text-muted)' }}
      title="Remove entry"
    >
      <Trash2 className="w-4 h-4" />
    </button>
  </div>
);
