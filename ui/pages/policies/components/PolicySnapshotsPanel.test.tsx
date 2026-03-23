import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { PolicyRecord } from '../../../types';
import { PolicySnapshotsPanel } from './PolicySnapshotsPanel';

function samplePolicy(): PolicyRecord {
  return {
    id: 'abcdef123456',
    name: 'Office Egress',
    created_at: '2026-03-05T12:34:56.000Z',
    mode: 'audit',
    policy: {
      default_policy: 'allow',
      source_groups: [],
    },
  };
}

describe('PolicySnapshotsPanel', () => {
  it('renders the snapshot list in its own hidden-scrollbar scroll container', () => {
    const html = renderToStaticMarkup(
      <PolicySnapshotsPanel
        loading={false}
        policies={[samplePolicy(), { ...samplePolicy(), id: 'fedcba654321', name: 'Branch Office' }]}
        selectedId={null}
        onSelect={vi.fn()}
      />,
    );

    expect(html).toContain('xl:max-h-[calc(100vh-7rem)]');
    expect(html).toContain('overflow-y-auto');
    expect(html).toContain('scrollbar-none');
    expect(html).toContain('overscroll-contain');
  });
});
