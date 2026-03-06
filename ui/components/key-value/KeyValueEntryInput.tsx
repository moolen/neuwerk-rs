import React from 'react';

interface KeyValueEntryInputProps {
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
  placeholder: string;
  error?: string;
  listId?: string;
}

export const KeyValueEntryInput: React.FC<KeyValueEntryInputProps> = ({
  value,
  onChange,
  disabled,
  placeholder,
  error,
  listId,
}) => (
  <div>
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      placeholder={placeholder}
      list={listId}
      className="w-full px-2 py-1 rounded text-sm"
      style={{
        background: 'var(--bg-input)',
        border: `1px solid ${error ? 'var(--red)' : 'var(--border-subtle)'}`,
        color: 'var(--text)',
      }}
    />
    {error && (
      <p className="text-xs mt-1" style={{ color: 'var(--red)' }}>
        {error}
      </p>
    )}
  </div>
);
