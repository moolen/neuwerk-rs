import React from 'react';
import type { AppPage } from '../navigation';
import { AuditPage } from '../pages/AuditPage';
import { Dashboard } from '../pages/Dashboard';
import { DNSCachePage } from '../pages/DNSCachePage';
import { IntegrationsPage } from '../pages/IntegrationsPage';
import { PoliciesPage } from '../pages/PoliciesPage';
import { ServiceAccountsPage } from '../pages/ServiceAccountsPage';
import { SettingsPage } from '../pages/SettingsPage';
import { ThreatFindingsPage } from '../pages/ThreatFindingsPage';
import { ThreatSilencesPage } from '../pages/ThreatSilencesPage';
import { ThreatsOverviewPage } from '../pages/ThreatsOverviewPage';
import { WiretapPage } from '../pages/WiretapPage';

const PAGE_COMPONENTS: Record<AppPage, React.ComponentType> = {
  dashboard: Dashboard,
  policies: PoliciesPage,
  integrations: IntegrationsPage,
  threats: ThreatsOverviewPage,
  'threat-findings': ThreatFindingsPage,
  'threat-silences': ThreatSilencesPage,
  wiretap: WiretapPage,
  audit: AuditPage,
  dns: DNSCachePage,
  'service-accounts': ServiceAccountsPage,
  settings: SettingsPage,
};

export function renderAppPage(page: AppPage): React.ReactElement {
  const Component = PAGE_COMPONENTS[page] ?? Dashboard;
  return <Component />;
}
