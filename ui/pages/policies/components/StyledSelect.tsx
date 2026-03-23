import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';

interface StyledSelectOption {
  value: string;
  label: string;
  description?: string;
}

interface StyledSelectProps {
  value: string;
  options: StyledSelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  buttonClassName?: string;
  menuClassName?: string;
  disabled?: boolean;
}

export const StyledSelect: React.FC<StyledSelectProps> = ({
  value,
  options,
  onChange,
  placeholder = 'Select option',
  buttonClassName,
  menuClassName,
  disabled = false,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const listboxId = useId();

  const selectedOption = useMemo(
    () => options.find((option) => option.value === value),
    [options, value]
  );
  const displayLabel = selectedOption?.label || value || placeholder;
  const hasSelection = Boolean(selectedOption ?? value);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  return (
    <div ref={rootRef} className={`relative ${buttonClassName ?? ''}`}>
      <button
        type="button"
        data-custom-select-trigger="true"
        aria-haspopup="listbox"
        aria-controls={listboxId}
        aria-expanded={isOpen}
        disabled={disabled}
        onClick={() => {
          if (!disabled) {
            setIsOpen((open) => !open);
          }
        }}
        className="w-full flex items-center justify-between gap-3 rounded-xl px-3 py-2 text-left text-sm transition-colors disabled:cursor-not-allowed"
        style={{
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
          color: hasSelection ? 'var(--text)' : 'var(--text-muted)',
          opacity: disabled ? 0.7 : 1,
        }}
      >
        <span className="min-w-0 truncate">{displayLabel}</span>
        <ChevronDown
          className="h-4 w-4 shrink-0"
          style={{
            color: 'var(--text-muted)',
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 150ms ease',
          }}
        />
      </button>

      {isOpen && (
        <div
          id={listboxId}
          role="listbox"
          className={`absolute left-0 top-[calc(100%+0.45rem)] z-30 w-full overflow-hidden rounded-[1rem] p-1 shadow-xl ${menuClassName ?? ''}`}
          style={{
            background: 'color-mix(in srgb, var(--bg-glass-strong) 88%, var(--bg) 12%)',
            border: '1px solid var(--border-glass)',
            backdropFilter: 'blur(18px)',
          }}
        >
          {options.length ? (
            <div className="space-y-1">
              {options.map((option) => {
                const isSelected = option.value === value;

                return (
                  <button
                    key={option.value}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    onClick={() => {
                      onChange(option.value);
                      setIsOpen(false);
                    }}
                    className="flex w-full items-start justify-between gap-3 rounded-[0.9rem] px-3 py-2 text-left"
                    style={{
                      background: isSelected ? 'var(--accent-light)' : 'transparent',
                      border: '1px solid transparent',
                      color: isSelected ? 'var(--accent)' : 'var(--text)',
                    }}
                  >
                    <span className="min-w-0">
                      <span className="block text-sm">{option.label}</span>
                      {option.description && (
                        <span
                          className="mt-0.5 block text-xs leading-5"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          {option.description}
                        </span>
                      )}
                    </span>
                    {isSelected && <Check className="mt-0.5 h-4 w-4 shrink-0" />}
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="px-3 py-2 text-sm" style={{ color: 'var(--text-muted)' }}>
              No options available
            </div>
          )}
        </div>
      )}
    </div>
  );
};
