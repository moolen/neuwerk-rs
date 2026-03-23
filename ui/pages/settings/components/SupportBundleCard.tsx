import React from 'react';

interface SupportBundleCardProps {
  downloading: boolean;
  onDownload: () => void;
}

export const SupportBundleCard: React.FC<SupportBundleCardProps> = ({
  downloading,
  onDownload,
}) => (
  <div
    className="rounded-[1.5rem] p-6 h-full flex flex-col"
    style={{
      background: 'linear-gradient(145deg, var(--bg-glass), rgba(16,185,129,0.08))',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div className="flex flex-wrap gap-2 mb-4">
      <span
        className="px-2.5 py-1 rounded-full text-xs font-semibold"
        style={{
          color: 'var(--text-secondary)',
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        Recovery
      </span>
      <span
        className="px-2.5 py-1 rounded-full text-xs font-semibold"
        style={{
          color: 'var(--text-secondary)',
          background: 'var(--bg-glass-subtle)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        Cluster-wide
      </span>
    </div>
    <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--text)' }}>
      Support Bundle
    </h2>
    <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
      Build a cluster-global sysdump from the leader. The resulting archive embeds one redacted
      sysdump per cluster member plus a cluster overview and failure manifest.
    </p>
    <div
      className="rounded-[1rem] p-3 mb-4 text-sm"
      style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}
    >
      Use this when you need one export that captures node-level failures alongside the cluster summary.
    </div>
    <button
      type="button"
      className="mt-auto px-4 py-2 rounded-xl text-sm font-semibold text-white shadow-sm transition-colors self-start"
      style={{
        minHeight: 40,
        background: 'var(--accent)',
        cursor: downloading ? 'not-allowed' : 'pointer',
        opacity: downloading ? 0.65 : 1,
      }}
      disabled={downloading}
      onClick={onDownload}
    >
      {downloading ? 'Building Cluster Sysdump...' : 'Download Cluster Sysdump'}
    </button>
  </div>
);
