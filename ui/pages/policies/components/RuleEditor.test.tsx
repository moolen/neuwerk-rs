import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule } from '../../../utils/policyModel';
import { RuleEditor } from './RuleEditor';

describe('RuleEditor', () => {
  it('renders named surfaces for header, matching, and TLS handling', () => {
    const html = renderToStaticMarkup(
      <RuleEditor
        groupIndex={0}
        ruleIndex={0}
        rule={createEmptyRule('rule-a')}
        updateDraft={vi.fn()}
        moveRule={vi.fn()}
        duplicateRule={vi.fn()}
        deleteRule={vi.fn()}
      />,
    );

    expect(html).toContain('Rule 1');
    expect(html).toContain('Match criteria');
    expect(html).toContain('TLS handling');
    expect(html).toContain('2xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.9fr)]');
    expect(html).toContain('2xl:grid-cols-2');
    expect(html).not.toContain('sm:flex-row sm:items-start sm:justify-between');
  });
});
