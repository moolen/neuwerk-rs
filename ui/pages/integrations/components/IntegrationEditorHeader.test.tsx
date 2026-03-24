import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { IntegrationEditorHeader } from './IntegrationEditorHeader';

describe('IntegrationEditorHeader', () => {
  it('renders the edit header without the kind or token pills', () => {
    const html = renderToStaticMarkup(
      <IntegrationEditorHeader
        editorMode="edit"
        selectedName="homelab"
        kind="kubernetes"
        tokenConfigured
        onDelete={vi.fn()}
      />,
    );

    expect(html).toContain('homelab');
    expect(html).toContain('Editing homelab for policy-driven dynamic source resolution.');
    expect(html).toContain('Delete');
    expect(html).not.toContain('kubernetes');
    expect(html).not.toContain('Token ready');
    expect(html).not.toContain('Token required');
    expect(html).not.toContain('uppercase tracking-[0.18em]');
  });

  it('renders the create header without the create pill', () => {
    const html = renderToStaticMarkup(
      <IntegrationEditorHeader
        editorMode="create"
        selectedName={null}
        kind="kubernetes"
        tokenConfigured={false}
        onDelete={vi.fn()}
      />,
    );

    expect(html).toContain('New integration draft');
    expect(html).not.toContain('Create');
    expect(html).not.toContain('uppercase tracking-[0.18em]');
  });
});
