import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PolicyEditorHeader } from './PolicyEditorHeader';

describe('PolicyEditorHeader', () => {
  it('renders only the policy builder title without the edit subtitle', () => {
    const html = renderToStaticMarkup(
      <PolicyEditorHeader
        editorMode="edit"
        editorTargetId="abcdef123456"
      />,
    );

    expect(html).toContain('Policy Builder');
    expect(html).not.toContain('Editing abcdef12');
    expect(html).not.toContain('Creating a new policy');
  });
});
