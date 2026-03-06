export type AppPage =
  | 'dashboard'
  | 'policies'
  | 'integrations'
  | 'wiretap'
  | 'audit'
  | 'dns'
  | 'service-accounts'
  | 'settings';

export interface NavItemDefinition {
  id: AppPage;
  label: string;
  adminOnly?: boolean;
}

export const NAV_ITEMS: ReadonlyArray<NavItemDefinition> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'policies', label: 'Policies' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'wiretap', label: 'Wiretap' },
  { id: 'audit', label: 'Audit' },
  { id: 'dns', label: 'DNS Cache' },
  { id: 'service-accounts', label: 'Service Accounts', adminOnly: true },
  { id: 'settings', label: 'Settings' },
];

const APP_PAGE_SET = new Set<AppPage>(NAV_ITEMS.map((item) => item.id));

export function getPageFromPathname(pathname: string): AppPage {
  const path = pathname.replace(/^\//, '').replace(/\/$/, '');
  if (path === '' || !APP_PAGE_SET.has(path as AppPage)) {
    return 'dashboard';
  }
  return path as AppPage;
}

export function pageToPath(page: AppPage): string {
  return page === 'dashboard' ? '/' : `/${page}`;
}
