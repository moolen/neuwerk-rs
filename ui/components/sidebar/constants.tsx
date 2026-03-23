import {
  Globe,
  Key,
  LayoutDashboard,
  Link,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react';

import type { AppPage } from '../../navigation';

export const PAGE_ICONS: Record<AppPage, LucideIcon> = {
  dashboard: LayoutDashboard,
  policies: Shield,
  integrations: Link,
  threats: ShieldAlert,
  'threat-findings': ShieldAlert,
  'threat-silences': ShieldAlert,
  wiretap: Radio,
  audit: Search,
  dns: Globe,
  'service-accounts': Key,
  settings: Settings,
};

export const SIDEBAR_LOGO = (
  <svg viewBox="0 0 24 24" width="20" height="20" fill="white">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
