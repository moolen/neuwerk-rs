import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { CreateThreatSilenceModal } from './CreateThreatSilenceModal';

describe('CreateThreatSilenceModal', () => {
  it('renders candidate value, optional reason field, and suppression warning copy', () => {
    const html = renderToStaticMarkup(
      <CreateThreatSilenceModal
        open={true}
        title="Silence exact indicator"
        description="Create a global silence for future hostname matches."
        kind="exact"
        indicatorType="hostname"
        value="bad.example.com"
        reason="expected internal domain"
        saving={false}
        onValueChange={() => {}}
        onReasonChange={() => {}}
        onClose={() => {}}
        onSubmit={() => {}}
      />,
    );

    expect(html).toContain('Silence exact indicator');
    expect(html).toContain('bad.example.com');
    expect(html).toContain('Reason');
    expect(html).toContain('future matches will be dropped before finding creation');
  });
});
