import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { createEmptyRule } from '../../../utils/policyModel';
import { RuleEditor } from './RuleEditor';

describe('RuleEditor', () => {
  it('renders rule settings, match criteria, and TLS handling as an unboxed single-column flow', () => {
    const rule = createEmptyRule('rule-a');
    rule.match.tls = {
      mode: 'metadata',
      tls13_uninspectable: 'deny',
      fingerprint_sha256: [],
      trust_anchors_pem: [],
    };

    const html = renderToStaticMarkup(
      <RuleEditor
        groupIndex={0}
        ruleIndex={0}
        rule={rule}
        updateDraft={vi.fn()}
        moveRule={vi.fn()}
        duplicateRule={vi.fn()}
        deleteRule={vi.fn()}
      />,
    );

    expect(html).toContain('Rule settings');
    expect(html).toContain('Match criteria');
    expect(html).toContain('TLS handling');
    expect(html).not.toContain('2xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.9fr)]');
    expect(html).not.toContain('Advanced');
    expect(html).not.toContain('Priority override');
    expect(html).not.toContain('<select');
    expect(html).not.toContain('sm:flex-row sm:items-start sm:justify-between');
  });
});
