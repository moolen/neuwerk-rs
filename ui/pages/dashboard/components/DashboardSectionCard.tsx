import React from 'react';

interface DashboardSectionCardProps {
  title: string;
  children: React.ReactNode;
  titleMarginClassName?: string;
}

export const DashboardSectionCard: React.FC<DashboardSectionCardProps> = ({
  title,
  children,
  titleMarginClassName = 'mb-4',
}) => (
  <section
    className="p-6"
    style={{
      background: 'var(--bg-glass-strong)',
      border: '1px solid var(--border-glass)',
      borderRadius: 'var(--radius)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <h3 className={`text-lg font-semibold ${titleMarginClassName}`} style={{ color: 'var(--text)' }}>
      {title}
    </h3>
    {children}
  </section>
);
