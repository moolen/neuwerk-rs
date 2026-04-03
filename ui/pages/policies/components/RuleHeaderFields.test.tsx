import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule } from '../../../utils/policyModel';
import { RuleHeaderFields } from './RuleHeaderFields';

describe('RuleHeaderFields', () => {
  it('renders rule name, action, and mode side by side on wide layouts', () => {
    const html = renderToStaticMarkup(
      <RuleHeaderFields
        groupIndex={0}
        ruleIndex={0}
        rule={createEmptyRule('rule-a')}
        updateDraft={vi.fn()}
      />,
    );

    expect(html).toContain('md:grid-cols-[minmax(14rem,1.4fr)_minmax(10rem,0.8fr)_minmax(10rem,0.8fr)]');
    expect(html).toContain('Rule name');
    expect(html).toContain('Action');
    expect(html).toContain('Mode');
  });
});
