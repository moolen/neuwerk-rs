import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  colorBg: string;
  colorFg: string;
  delay: number;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon: Icon,
  colorBg,
  colorFg,
  delay,
}) => (
  <div
    className="p-5 flex items-center justify-between"
    style={{
      background: 'var(--bg-glass-strong)',
      backdropFilter: 'blur(12px)',
      WebkitBackdropFilter: 'blur(12px)',
      border: '1px solid var(--border-glass)',
      borderRadius: 'var(--radius)',
      boxShadow: 'var(--shadow-glass)',
      animation: `fadeSlideUp 0.5s ease-out ${delay * 0.05 + 0.05}s backwards`,
    }}
  >
    <div>
      <p className="text-sm font-medium" style={{ color: 'var(--text-muted)' }}>
        {title}
      </p>
      <h3 className="text-2xl font-bold mt-1" style={{ color: 'var(--text)', letterSpacing: '-0.5px' }}>
        {value}
      </h3>
    </div>
    <div className="p-3" style={{ background: colorBg, color: colorFg, borderRadius: 'var(--radius-sm)' }}>
      <Icon className="w-5 h-5" />
    </div>
  </div>
);
