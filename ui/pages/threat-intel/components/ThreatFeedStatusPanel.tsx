import React from 'react';

import type { ThreatFeedStatusResponse } from '../../../types';

interface ThreatFeedStatusPanelProps {
  feedStatus: ThreatFeedStatusResponse | null;
}

function freshnessLabel(
  ageSeconds: number | null | undefined,
  enabled: boolean,
): string {
  if (!enabled) {
    return 'Disabled';
  }
  if (typeof ageSeconds !== 'number') {
    return 'Awaiting freshness telemetry';
  }
  if (ageSeconds < 60) {
    return `${ageSeconds}s old`;
  }
  if (ageSeconds < 60 * 60) {
    return `${Math.floor(ageSeconds / 60)}m old`;
  }
  if (ageSeconds < 24 * 60 * 60) {
    return `${Math.floor(ageSeconds / 3600)}h old`;
  }
  return `${Math.floor(ageSeconds / 86400)}d old`;
}

function freshnessTone(
  ageSeconds: number | null | undefined,
  enabled: boolean,
): React.CSSProperties {
  if (!enabled) {
    return { color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)' };
  }
  if (typeof ageSeconds !== 'number') {
    return { color: 'var(--amber)', background: 'var(--amber-bg)' };
  }
  if (ageSeconds <= 6 * 60 * 60) {
    return { color: 'var(--green)', background: 'var(--green-bg)' };
  }
  return { color: 'var(--amber)', background: 'var(--amber-bg)' };
}

function formatUnixTime(value: number | null | undefined): string {
  if (typeof value !== 'number') {
    return 'n/a';
  }
  return new Date(value * 1000).toLocaleString();
}

export const ThreatFeedStatusPanel: React.FC<ThreatFeedStatusPanelProps> = ({
  feedStatus,
}) => (
  <section className="space-y-4">
    <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
          Feed Freshness
        </h2>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Snapshot version {feedStatus?.snapshot_version ?? 0}
        </p>
      </div>

      <div
        className="rounded-[1.2rem] px-4 py-3 text-sm grid gap-2 md:grid-cols-3"
        style={{
          background: 'linear-gradient(155deg, rgba(79,110,247,0.1), rgba(255,255,255,0.08))',
          border: '1px solid var(--border-glass)',
        }}
      >
        <div>
          <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
            Last Outcome
          </div>
          <div className="mt-1 font-semibold" style={{ color: 'var(--text)' }}>
            {feedStatus?.last_refresh_outcome ?? 'pending'}
          </div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
            Last Success
          </div>
          <div className="mt-1 font-semibold" style={{ color: 'var(--text)' }}>
            {formatUnixTime(feedStatus?.last_successful_refresh_at)}
          </div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
            Last Refresh
          </div>
          <div className="mt-1 font-semibold" style={{ color: 'var(--text)' }}>
            {formatUnixTime(feedStatus?.last_refresh_completed_at)}
          </div>
        </div>
      </div>
    </div>

    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {(feedStatus?.feeds ?? []).map((feed) => (
        <article
          key={feed.feed}
          className="rounded-[1.4rem] p-4"
          style={{
            background:
              'linear-gradient(155deg, var(--bg-glass-strong), rgba(255,255,255,0.12))',
            border: '1px solid var(--border-glass)',
            boxShadow: 'var(--shadow-glass)',
          }}
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <div
                className="text-xs uppercase tracking-[0.24em]"
                style={{ color: 'var(--text-muted)' }}
              >
                Feed
              </div>
              <div className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
                {feed.feed}
              </div>
            </div>
            <span
              className="px-2.5 py-1 rounded-full text-xs font-semibold"
              style={freshnessTone(feed.snapshot_age_seconds, feed.enabled)}
            >
              {feed.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>

          <div className="mt-6 text-sm font-medium" style={{ color: 'var(--text)' }}>
            {freshnessLabel(feed.snapshot_age_seconds, feed.enabled)}
          </div>
          <div className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            {typeof feed.snapshot_age_seconds === 'number'
              ? 'Based on the latest published snapshot age.'
              : 'Backend freshness telemetry has not been populated yet.'}
          </div>

          <div className="mt-5 grid grid-cols-2 gap-3">
            <div
              className="rounded-xl px-3 py-2"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                Hostnames
              </div>
              <div className="mt-1 text-lg font-semibold" style={{ color: 'var(--text)' }}>
                {feed.indicator_counts.hostname}
              </div>
            </div>
            <div
              className="rounded-xl px-3 py-2"
              style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
            >
              <div className="text-[11px] uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
                IPs
              </div>
              <div className="mt-1 text-lg font-semibold" style={{ color: 'var(--text)' }}>
                {feed.indicator_counts.ip}
              </div>
            </div>
          </div>

          <div className="mt-4 text-xs" style={{ color: 'var(--text-secondary)' }}>
            Last outcome: {feed.last_refresh_outcome ?? 'pending'}
          </div>
        </article>
      ))}
    </div>
  </section>
);
