import React from 'react';
import type { WiretapFilterValues } from './types';

interface WiretapFilterFieldsProps {
  filters: WiretapFilterValues;
  onChange: (next: WiretapFilterValues) => void;
  disabled?: boolean;
}

interface FieldDef {
  id: keyof WiretapFilterValues;
  label: string;
  placeholder: string;
}

const FIELD_DEFS: readonly FieldDef[] = [
  { id: 'source_ip', label: 'Source IP', placeholder: 'Filter by source IP' },
  { id: 'dest_ip', label: 'Destination IP', placeholder: 'Filter by dest IP' },
  { id: 'hostname', label: 'Hostname', placeholder: 'Filter by hostname' },
  { id: 'port', label: 'Port', placeholder: 'Filter by port' },
];

export const WiretapFilterFields: React.FC<WiretapFilterFieldsProps> = ({
  filters,
  onChange,
  disabled = false,
}) => {
  const updateField = (id: keyof WiretapFilterValues, value: string) => {
    onChange({ ...filters, [id]: value });
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
      {FIELD_DEFS.map(({ id, label, placeholder }) => (
        <div key={id}>
          <label htmlFor={id} className="block text-xs font-medium text-slate-400 mb-1">
            {label}
          </label>
          <input
            id={id}
            type="text"
            value={filters[id]}
            onChange={(e) => updateField(id, e.target.value)}
            disabled={disabled}
            placeholder={placeholder}
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      ))}
    </div>
  );
};
