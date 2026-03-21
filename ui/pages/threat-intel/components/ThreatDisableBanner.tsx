import React from 'react';

interface ThreatDisableBannerProps {
  disabled: boolean;
  onOpenSettings: () => void;
}

export const ThreatDisableBanner: React.FC<ThreatDisableBannerProps> = ({
  disabled,
  onOpenSettings,
}) => {
  if (!disabled) {
    return null;
  }

  return (
    <section
      className="rounded-[1.6rem] p-5 md:p-6"
      style={{
        background:
          'linear-gradient(145deg, rgba(15,23,42,0.92), rgba(30,64,175,0.78), rgba(12,74,110,0.7))',
        border: '1px solid rgba(148,163,184,0.2)',
        boxShadow: '0 22px 70px rgba(15,23,42,0.28)',
      }}
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-2">
          <div
            className="inline-flex px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-[0.24em]"
            style={{ color: '#dbeafe', background: 'rgba(148,163,184,0.14)' }}
          >
            Analysis paused
          </div>
          <h2 className="text-2xl font-semibold" style={{ color: '#f8fafc' }}>
            Threat analysis disabled
          </h2>
          <p className="max-w-3xl text-sm" style={{ color: 'rgba(226,232,240,0.84)' }}>
            new URLs and IPs are not processed while this feature is disabled. Existing findings
            stay on disk and will become visible again after you re-enable threat analysis.
          </p>
        </div>

        <button
          type="button"
          className="px-4 py-2.5 rounded-full text-sm font-semibold self-start"
          style={{
            background: '#f8fafc',
            color: '#0f172a',
            boxShadow: '0 12px 32px rgba(15,23,42,0.22)',
          }}
          onClick={onOpenSettings}
        >
          Open threat settings
        </button>
      </div>
    </section>
  );
};
