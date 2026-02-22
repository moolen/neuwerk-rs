import React from 'react';

export const SettingsPage: React.FC = () => {
  return (
    <div className="p-6" style={{ color: 'var(--text)' }}>
      <h1 className="text-3xl font-bold mb-4" style={{ color: 'var(--text)' }}>Settings</h1>
      <div className="rounded-xl p-8 text-sm" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}>
        Diagnostics will land here in a future release.
      </div>
    </div>
  );
};
