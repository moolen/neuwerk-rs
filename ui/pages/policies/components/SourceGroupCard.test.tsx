import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule, createEmptySourceGroup } from '../../../utils/policyModel';
import { SourceGroupCard } from './SourceGroupCard';

describe('SourceGroupCard', () => {
  it('renders named surfaces for group identity, source selectors, and rules', () => {
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

    expect(html).toContain('Source group 1');
    expect(html).toContain('Source selectors');
    expect(html).toContain('Rule stack');
    expect(html).toContain('2xl:grid-cols-[minmax(0,1.15fr)_minmax(19rem,0.95fr)]');
    expect(html).toContain('2xl:grid-cols-3');
    expect(html).toContain('2xl:grid-cols-2');
    expect(html).not.toContain('sm:flex-row sm:items-start sm:justify-between');
  });
});
