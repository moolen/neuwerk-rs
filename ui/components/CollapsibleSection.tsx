import React from 'react';
import { ChevronDown } from 'lucide-react';

interface CollapsibleSectionProps {
  title: string;
  subtitle?: string;
  isOpen: boolean;
  onToggle: () => void;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

export const CollapsibleSection: React.FC<CollapsibleSectionProps> = ({
  title,
  subtitle,
  isOpen,
  onToggle,
  actions,
  children,
}) => {
  return (
    <div className="rounded-lg" style={{ border: '1px solid var(--border-subtle)' }}>
      <div className="flex items-center justify-between px-3 py-2" style={{ background: 'var(--bg-glass-subtle)' }}>
        <button
          type="button"
          onClick={onToggle}
          className="flex items-center gap-2 text-sm font-semibold"
          style={{ color: 'var(--text)' }}
        >
          <ChevronDown className="w-4 h-4" style={{ transform: isOpen ? 'rotate(0deg)' : 'rotate(-90deg)' }} />
          <span>{title}</span>
          {subtitle && <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>{subtitle}</span>}
        </button>
        {actions}
      </div>
      {isOpen && <div className="p-3 space-y-3">{children}</div>}
    </div>
  );
};
