import React from 'react';

import { listToText, textToList } from '../helpers';
import { KubernetesSourcesEditor } from './KubernetesSourcesEditor';
import type { SourceGroupContextProps } from './sourceGroupTypes';

export const SourceGroupSourcesSection: React.FC<SourceGroupContextProps> = ({
  group,
  groupIndex,
  integrations,
  updateDraft,
}) => (
  <>
    <div className="grid grid-cols-1 2xl:grid-cols-2 gap-3">
      <div>
        <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Source CIDRs (line/comma separated)
        </label>
        <textarea
          value={listToText(group.sources.cidrs)}
          onChange={(e) =>
            updateDraft((next) => {
              next.policy.source_groups[groupIndex].sources.cidrs = textToList(e.target.value);
            })
          }
          rows={3}
          className="w-full px-3 py-2 rounded-xl text-sm"
          style={{
            background: 'var(--bg-glass-subtle)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
      </div>
      <div>
        <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
          Source IPv4s (line/comma separated)
        </label>
        <textarea
          value={listToText(group.sources.ips)}
          onChange={(e) =>
            updateDraft((next) => {
              next.policy.source_groups[groupIndex].sources.ips = textToList(e.target.value);
            })
          }
          rows={3}
          className="w-full px-3 py-2 rounded-xl text-sm"
          style={{
            background: 'var(--bg-glass-subtle)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text)',
          }}
        />
      </div>
    </div>

    <KubernetesSourcesEditor
      groupIndex={groupIndex}
      group={group}
      integrations={integrations}
      updateDraft={updateDraft}
    />
  </>
);
