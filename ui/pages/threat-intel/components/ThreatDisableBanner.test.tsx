import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ThreatDisableBanner } from './ThreatDisableBanner';

describe('ThreatDisableBanner', () => {
  it('renders the disabled threat-analysis state copy', () => {
    const html = renderToStaticMarkup(
      <ThreatDisableBanner disabled={true} onOpenSettings={() => {}} />,
    );

    expect(html).toContain('Threat analysis disabled');
    expect(html).toContain('new URLs and IPs are not processed');
    expect(html).toContain('Open threat settings');
  });
});
