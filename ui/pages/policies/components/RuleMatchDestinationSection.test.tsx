import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule } from '../../../utils/policyModel';
import { RuleMatchDestinationSection } from './RuleMatchDestinationSection';

describe('RuleMatchDestinationSection', () => {
  it('renders destination CIDR and destination IP fields as tokenized inputs instead of textareas', () => {
    const html = renderToStaticMarkup(
      <RuleMatchDestinationSection
        groupIndex={0}
        ruleIndex={0}
        rule={createEmptyRule('rule-a')}
        updateDraft={vi.fn()}
      />,
    );

    expect(html).toContain('data-token-list-input="true"');
    expect(html).toContain('Press Enter or Tab to add');
    expect(html).not.toContain('<textarea');
  });
});
