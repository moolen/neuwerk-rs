import React from 'react';
import type { AppPage } from '../navigation';
import { AuditPage } from '../pages/AuditPage';
import { Dashboard } from '../pages/Dashboard';
import { DNSCachePage } from '../pages/DNSCachePage';
import { IntegrationsPage } from '../pages/IntegrationsPage';
import { PoliciesPage } from '../pages/PoliciesPage';
import { ServiceAccountsPage } from '../pages/ServiceAccountsPage';
import { SettingsPage } from '../pages/SettingsPage';
import { ThreatIntelPage } from '../pages/ThreatIntelPage';
import { WiretapPage } from '../pages/WiretapPage';

const PAGE_COMPONENTS: Record<AppPage, React.ComponentType> = {
  dashboard: Dashboard,
  policies: PoliciesPage,
  integrations: IntegrationsPage,
  threats: ThreatIntelPage,
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
