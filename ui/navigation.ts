export type AppPage =
  | 'dashboard'
  | 'policies'
  | 'integrations'
  | 'threats'
  | 'threat-findings'
  | 'threat-silences'
  | 'wiretap'
  | 'audit'
  | 'dns'
  | 'service-accounts'
  | 'settings';

export interface NavItemDefinition {
  id: AppPage;
  label: string;
  parentId?: AppPage;
  adminOnly?: boolean;
}

const PAGE_PATHS: Record<AppPage, string> = {
  dashboard: '/',
  policies: '/policies',
  integrations: '/integrations',
  threats: '/threats',
  'threat-findings': '/threats/findings',
  'threat-silences': '/threats/silences',
  wiretap: '/wiretap',
  audit: '/audit',
  dns: '/dns',
  'service-accounts': '/service-accounts',
  settings: '/settings',
};

export const NAV_ITEMS: ReadonlyArray<NavItemDefinition> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'policies', label: 'Policies' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'threats', label: 'Threats' },
  { id: 'threat-findings', label: 'Findings', parentId: 'threats' },
  { id: 'threat-silences', label: 'Silences', parentId: 'threats' },
  { id: 'wiretap', label: 'Wiretap' },
  { id: 'audit', label: 'Audit' },
  { id: 'dns', label: 'DNS Cache' },
  { id: 'service-accounts', label: 'Service Accounts', adminOnly: true },
  { id: 'settings', label: 'Settings' },
];

export function getPageLabel(page: AppPage): string {
  return NAV_ITEMS.find((item) => item.id === page)?.label ?? 'Dashboard';
}

export function getPageFromPathname(pathname: string): AppPage {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/threat-intel') return 'threats';
  return (
    (Object.entries(PAGE_PATHS).find(([, candidate]) => candidate === path)?.[0] as AppPage) ??
    'dashboard'
  );
}

export function pageToPath(page: AppPage): string {
  return PAGE_PATHS[page] ?? '/';
}
