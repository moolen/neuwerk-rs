import { createAuthRoutes } from './routes/auth';
import { createAuditRoutes } from './routes/audit';
import { createDnsRoutes } from './routes/dns';
import { createSettingsReadRoutes } from './routes/settings-read';
import { createStatsRoutes } from './routes/stats';
import { createThreatRoutes } from './routes/threats';
import type { MockState } from './state';
import type { MockRoute } from './types';

export function createReadDomainRoutes(state: MockState): MockRoute[] {
  return [
    ...createAuthRoutes(state),
    ...createStatsRoutes(state),
    ...createDnsRoutes(state),
    ...createAuditRoutes(state),
    ...createThreatRoutes(state),
    ...createSettingsReadRoutes(state),
  ];
}
