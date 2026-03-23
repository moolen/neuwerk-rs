import React, { useState } from 'react';
import { X } from 'lucide-react';

import {
  commitNetworkToken,
  type NetworkTokenValidator,
} from './networkTokenUtils';

interface NetworkTokenListInputProps {
  values: string[];
  onChange: (nextValues: string[]) => void;
  validator: NetworkTokenValidator;
  placeholder: string;
  helperText: string;
  inputClassName?: string;
  inputStyle?: React.CSSProperties;
  chipStyle?: React.CSSProperties;
}

export const NetworkTokenListInput: React.FC<NetworkTokenListInputProps> = ({
  values,
  onChange,
  validator,
  placeholder,
  helperText,
  inputClassName,
  inputStyle,
  chipStyle,
}) => {
  const [draftValue, setDraftValue] = useState('');
  const [error, setError] = useState<string | undefined>();

  const commitValue = () => {
    const result = commitNetworkToken(draftValue, values, validator);
    setError(result.error);
    if (result.added) {
      onChange(result.nextTokens);
      setDraftValue('');
    }
    if (!draftValue.trim()) {
      setError(undefined);
    }
    return result;
  };

  return (
    <div data-token-list-input="true" className="space-y-2">
      <input
        type="text"
        value={draftValue}
        onChange={(event) => {
          setDraftValue(event.target.value);
          if (error) {
            setError(undefined);
          }
        }}
        onKeyDown={(event) => {
          if (event.key !== 'Enter' && event.key !== 'Tab') {
            return;
          }

          const result = commitValue();
          if (event.key === 'Enter' || result.error) {
            event.preventDefault();
          }
        }}
        placeholder={placeholder}
        className={`w-full rounded-xl px-3 py-2 text-sm ${inputClassName ?? ''}`}
        style={inputStyle}
      />

      <div className="text-xs leading-5" style={{ color: error ? 'var(--red)' : 'var(--text-muted)' }}>
        {error ?? helperText}
      </div>

      {values.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <span
              key={value}
              className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs"
              style={chipStyle}
            >
              <span>{value}</span>
              <button
                type="button"
                onClick={() => onChange(values.filter((entry) => entry !== value))}
                className="inline-flex h-4 w-4 items-center justify-center rounded-full"
                style={{ color: 'inherit' }}
                aria-label={`Remove ${value}`}
                title={`Remove ${value}`}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};
