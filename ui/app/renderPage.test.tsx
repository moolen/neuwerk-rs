import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { renderAppPage } from './renderPage';
import { createDefaultThreatFilters } from '../pages/threat-intel/helpers';
import { useThreatFindingsPage } from '../pages/threat-intel/useThreatFindingsPage';
import { useThreatOverviewPage } from '../pages/threat-intel/useThreatOverviewPage';
import { useThreatSilencesPage } from '../pages/threat-intel/useThreatSilencesPage';

vi.mock('../pages/threat-intel/useThreatOverviewPage', () => ({
  useThreatOverviewPage: vi.fn(),
}));

vi.mock('../pages/threat-intel/useThreatFindingsPage', () => ({
  useThreatFindingsPage: vi.fn(),
}));

vi.mock('../pages/threat-intel/useThreatSilencesPage', () => ({
  useThreatSilencesPage: vi.fn(),
}));

describe('renderPage', () => {
  it('renders the threat child pages from renderPage', () => {
    vi.mocked(useThreatOverviewPage).mockReturnValue({
      feedStatus: { snapshot_version: 9, feeds: [], disabled: false },
      disabled: false,
      partial: false,
      nodeErrors: [],
      nodesQueried: 2,
      nodesResponded: 2,
      findingsCount: 1,
      loading: false,
      error: null,
      refresh: async () => {},
    });
    vi.mocked(useThreatFindingsPage).mockReturnValue({
      items: [],
      rawItems: [],
      filters: createDefaultThreatFilters(''),
      availableFeeds: [],
      availableSourceGroups: [],
      loading: false,
      error: null,
      partial: false,
      nodeErrors: [],
      nodesQueried: 2,
      nodesResponded: 2,
      disabled: false,
      silenceSaving: false,
      load: async () => {},
      updateFilters: () => {},
      createSilence: async () => {},
    });
    vi.mocked(useThreatSilencesPage).mockReturnValue({
      silences: [],
      loading: false,
      error: null,
      deletingSilenceId: null,
      silenceSaving: false,
      createSilence: async () => {},
      deleteSilence: async () => {},
    });

    expect(renderToStaticMarkup(renderAppPage('threats'))).toContain('Feed Freshness');
    expect(renderToStaticMarkup(renderAppPage('threat-findings'))).toContain('Findings');
    expect(renderToStaticMarkup(renderAppPage('threat-silences'))).toContain('Silences');
  });
});
