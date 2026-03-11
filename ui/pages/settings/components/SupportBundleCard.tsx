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
    className="rounded-xl p-6"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--text)' }}>
      Support Bundle
    </h2>
    <p className="text-sm mb-4" style={{ color: 'var(--text-muted)' }}>
      Build a cluster-global sysdump from the leader. The resulting archive embeds one redacted
      sysdump per cluster member plus a cluster overview and failure manifest.
    </p>
    <button
      type="button"
      className="px-4 py-2 rounded-lg text-sm font-semibold text-white shadow-sm transition-colors"
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
