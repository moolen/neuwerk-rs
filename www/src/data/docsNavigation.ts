export interface DocsNavItem {
  href: string;
  label: string;
}

export interface DocsNavSection {
  title: string;
  items: DocsNavItem[];
}

export const docsNavigation: DocsNavSection[] = [
  {
    title: 'Architecture',
    items: [
      { href: '/docs/architecture/system-overview', label: 'System Overview' },
      { href: '/docs/architecture/traffic-flows', label: 'Traffic Flows' },
      { href: '/docs/architecture/dataplane', label: 'Dataplane' },
      { href: '/docs/architecture/control-plane', label: 'Control Plane' },
      { href: '/docs/architecture/cluster-replication', label: 'Cluster Replication' },
    ],
  },
  {
    title: 'Configuration',
    items: [
      { href: '/docs/configuration/policy-model', label: 'Policy Model' },
      { href: '/docs/configuration/dns-handling', label: 'DNS Handling' },
      { href: '/docs/configuration/tls-interception', label: 'TLS Interception' },
    ],
  },
  {
    title: 'Deployment',
    items: [
      { href: '/docs/deployment/single-node', label: 'Single Node' },
      { href: '/docs/deployment/high-availability', label: 'High Availability' },
      { href: '/docs/deployment/kubernetes', label: 'Kubernetes' },
    ],
  },
  {
    title: 'Operations',
    items: [
      { href: '/docs/operations/observability', label: 'Observability' },
      { href: '/docs/operations/logging-audit', label: 'Logging & Audit' },
      { href: '/docs/operations/backup-restore', label: 'Backup & Restore' },
      { href: '/docs/operations/upgrade-rollback-dr', label: 'Upgrade, Rollback & DR' },
      { href: '/docs/operations/alerts', label: 'Alerts' },
      { href: '/docs/operations/troubleshooting', label: 'Troubleshooting' },
    ],
  },
  {
    title: 'Interfaces',
    items: [
      { href: '/docs/interfaces/http-api', label: 'HTTP API' },
      { href: '/docs/interfaces/web-ui', label: 'Web UI' },
      { href: '/docs/interfaces/terraform-provider', label: 'Terraform Provider' },
    ],
  },
  {
    title: 'Reference',
    items: [
      { href: '/docs/reference/configuration-schema', label: 'Configuration Schema' },
      { href: '/docs/reference/ports-protocols', label: 'Ports & Protocols' },
      { href: '/docs/reference/glossary', label: 'Glossary' },
    ],
  },
];

export function isDocsPathActive(href: string, current: string): boolean {
  return current === href || (href !== '/docs' && current.startsWith(`${href}/`));
}
