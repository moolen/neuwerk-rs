import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule, createEmptySourceGroup } from '../../../utils/policyModel';
import { SourceGroupCard } from './SourceGroupCard';

describe('SourceGroupCard', () => {
  it('renders group settings and source selectors side by side with a full-width rule stack below', () => {
    const group = createEmptySourceGroup('group-a');
    group.rules = [createEmptyRule('rule-a')];

    const html = renderToStaticMarkup(
      <SourceGroupCard
        group={group}
        groupIndex={0}
        integrations={[]}
        updateDraft={vi.fn()}
        duplicateGroup={vi.fn()}
        moveGroup={vi.fn()}
        deleteGroup={vi.fn()}
        addRule={vi.fn()}
        duplicateRule={vi.fn()}
        moveRule={vi.fn()}
        deleteRule={vi.fn()}
      />,
    );

    expect(html).toContain('group-a');
    expect(html).toContain('Source selectors');
    expect(html).toContain('Rule stack');
    expect(html).toContain('xl:grid-cols-[minmax(15rem,0.9fr)_minmax(0,1.1fr)]');
    expect(html).not.toContain('rounded-[1.1rem] p-4');
    expect(html).not.toContain('Advanced');
    expect(html).not.toContain('Priority override');
    expect(html).not.toContain('sm:flex-row sm:items-start sm:justify-between');
    expect(html).not.toContain('2xl:grid-cols-[minmax(0,1.15fr)_minmax(19rem,0.95fr)]');
  });

  it('keeps the source-group name in its own header block when collapsed', async () => {
    vi.resetModules();
    vi.doMock('react', async () => {
      const actual = await vi.importActual<typeof import('react')>('react');
      return {
        ...actual,
        useState: () => [false, vi.fn()],
      };
    });

    try {
      const { SourceGroupCard: CollapsedSourceGroupCard } = await import('./SourceGroupCard');
      const group = createEmptySourceGroup('homelab');
      group.rules = [createEmptyRule('allow-dns')];
      group.sources.cidrs = ['10.0.0.0/24'];

      const html = renderToStaticMarkup(
        <CollapsedSourceGroupCard
          group={group}
          groupIndex={0}
          integrations={[]}
          updateDraft={vi.fn()}
          duplicateGroup={vi.fn()}
          moveGroup={vi.fn()}
          deleteGroup={vi.fn()}
          addRule={vi.fn()}
          duplicateRule={vi.fn()}
          moveRule={vi.fn()}
          deleteRule={vi.fn()}
        />,
      );

      expect(html).toContain('homelab');
      expect(html).toContain('fallback: deny');
      expect(html).toContain('sm:flex-row sm:items-start');
      expect(html).not.toContain('flex items-center gap-2.5 px-4 py-3 cursor-pointer select-none');
    } finally {
      vi.doUnmock('react');
      vi.resetModules();
    }
  });
});
