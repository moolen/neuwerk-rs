import React from 'react';

interface DashboardSectionCardProps {
  title: string;
  children: React.ReactNode;
  titleMarginClassName?: string;
  description?: string;
}

export const DashboardSectionCard: React.FC<DashboardSectionCardProps> = ({
  title,
  children,
  titleMarginClassName = 'mb-4',
  description,
}) => (
  <section
    className="p-6 h-full"
    style={{
      background: 'var(--bg-glass-strong)',
      border: '1px solid var(--border-glass)',
      borderRadius: '1.4rem',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className={titleMarginClassName}>
      <h3 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
        {title}
      </h3>
      {description ? (
        <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
          {description}
        </p>
      ) : null}
    </div>
    {children}
  </section>
);
