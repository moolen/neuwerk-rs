import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptySourceGroup } from '../../../utils/policyModel';
import { SourceGroupSourcesSection } from './SourceGroupSourcesSection';

describe('SourceGroupSourcesSection', () => {
  it('renders source CIDR and source IP fields as tokenized inputs instead of textareas', () => {
    const html = renderToStaticMarkup(
      <SourceGroupSourcesSection
        group={createEmptySourceGroup('group-a')}
        groupIndex={0}
        integrations={[]}
        updateDraft={vi.fn()}
      />,
    );

    expect(html).toContain('data-token-list-input="true"');
    expect(html).toContain('Press Enter or Tab to add');
    expect(html).not.toContain('<textarea');
    expect(html).not.toContain('line/comma separated');
  });
});
