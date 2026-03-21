import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ThreatSilenceEntry } from '../../../types';
import { ThreatSilencesPanel } from './ThreatSilencesPanel';

function silence(overrides: Partial<ThreatSilenceEntry> = {}): ThreatSilenceEntry {
  return {
    id: 'silence-1',
    kind: 'exact',
    indicator_type: 'hostname',
    value: 'bad.example.com',
    reason: 'known false positive',
    created_at: 1_700_000_000,
    created_by: null,
    ...overrides,
  };
}

describe('ThreatSilencesPanel', () => {
  it('renders the silence list details and delete affordance', () => {
    const html = renderToStaticMarkup(
      <ThreatSilencesPanel
        items={[silence(), silence({ id: 'silence-2', kind: 'hostname_regex', indicator_type: null, value: '^.*\\.example\\.com$' })]}
        loading={false}
        deletingId={null}
        onDelete={() => {}}
        onCreateManual={() => {}}
      />,
    );

    expect(html).toContain('Silences');
    expect(html).toContain('known false positive');
    expect(html).toContain('bad.example.com');
    expect(html).toContain('^.*\\.example\\.com$');
    expect(html).toContain('Delete');
    expect(html).toContain('Add silence');
  });
});
