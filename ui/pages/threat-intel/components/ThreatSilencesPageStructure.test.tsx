import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ThreatSilenceEntry } from '../../../types';
import { ThreatSilencesPage } from '../../ThreatSilencesPage';
import { useThreatSilencesPage } from '../useThreatSilencesPage';

vi.mock('../useThreatSilencesPage', () => ({
  useThreatSilencesPage: vi.fn(),
}));

function threatSilenceFixture(overrides: Partial<ThreatSilenceEntry> = {}): ThreatSilenceEntry {
  return {
    id: 'silence-1',
    kind: 'exact',
    indicator_type: 'hostname',
    value: 'bad.example.com',
    reason: 'known test',
    created_at: 1_700_000_000,
    created_by: 'test',
    ...overrides,
  };
}

describe('ThreatSilencesPage structure', () => {
  it('renders the silence-management workflow on its own page', () => {
    vi.mocked(useThreatSilencesPage).mockReturnValue({
      silences: [threatSilenceFixture()],
      loading: false,
      error: null,
      deletingSilenceId: null,
      silenceSaving: false,
      createSilence: async () => {},
      deleteSilence: async () => {},
    });

    const html = renderToStaticMarkup(<ThreatSilencesPage />);
    expect(html).toContain('Silences');
    expect(html).toContain('Add silence');
    expect(html).not.toContain('Feed Freshness');
    expect(html).not.toContain('Investigate');
  });
});
