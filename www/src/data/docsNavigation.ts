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
    title: 'Getting Started',
    items: [
      { href: '/docs/tutorials/run-the-vagrant-demo-box', label: 'Run The Vagrant Demo Box' },
      {
        href: '/docs/tutorials/launch-from-released-cloud-image',
        label: 'Launch Neuwerk From The Released Cloud Image',
      },
      { href: '/docs/tutorials/create-your-first-policy', label: 'Create Your First Policy' },
    ],
  },
  {
    title: 'How-To Guides',
    items: [
      {
        href: '/docs/how-to/customize-the-appliance-image-at-first-boot',
        label: 'Customize The Appliance Image At First Boot',
      },
      { href: '/docs/how-to/get-admin-access', label: 'Get Admin Access' },
      { href: '/docs/how-to/policy-examples', label: 'Policy Examples' },
      { href: '/docs/how-to/roll-out-a-policy-with-audit-mode', label: 'Roll Out A Policy Safely' },
      { href: '/docs/deployment/requirements', label: 'Deployment Requirements' },
      { href: '/docs/deployment/single-node', label: 'Run A Single Node' },
      { href: '/docs/deployment/high-availability', label: 'Run An HA Cluster' },
      { href: '/docs/how-to/upgrade-a-cluster', label: 'Upgrade A Cluster' },
      { href: '/docs/configuration/dns-handling', label: 'Configure DNS Enforcement' },
      { href: '/docs/configuration/tls-interception', label: 'Enable TLS Interception' },
      { href: '/docs/how-to/use-kubernetes-backed-sources', label: 'Use Kubernetes-Backed Sources' },
      { href: '/docs/operations/backup-restore', label: 'Back Up And Restore State' },
      { href: '/docs/operations/troubleshooting', label: 'Troubleshoot Enforcement' },
    ],
  },
  {
    title: 'Concepts',
    items: [
      { href: '/docs/architecture/system-overview', label: 'System Overview' },
      { href: '/docs/architecture/traffic-flows', label: 'Traffic Flows' },
      { href: '/docs/architecture/dataplane', label: 'Dataplane' },
      { href: '/docs/architecture/control-plane', label: 'Control Plane' },
      { href: '/docs/architecture/cluster-replication', label: 'Cluster Replication' },
      { href: '/docs/architecture/cloud-rollout-integration', label: 'Cloud Rollout Integration' },
      { href: '/docs/configuration/policy-model', label: 'Policy Model' },
      { href: '/docs/deployment/kubernetes', label: 'Kubernetes-Backed Sources' },
      { href: '/docs/operations/observability', label: 'Observability Model' },
      { href: '/docs/operations/performance-mode', label: 'Performance Mode' },
      { href: '/docs/operations/logging-audit', label: 'Logs, Audit, And Wiretap' },
      { href: '/docs/operations/alerts', label: 'Alerting Signals' },
    ],
  },
  {
    title: 'Reference',
    items: [
      { href: '/docs/interfaces/http-api', label: 'HTTP API' },
      { href: '/docs/interfaces/web-ui', label: 'Web UI' },
      { href: '/docs/interfaces/terraform-provider', label: 'Terraform Provider' },
      { href: '/docs/reference/configuration-schema', label: 'Configuration Schema' },
      { href: '/docs/reference/runtime-configuration', label: 'Runtime Configuration Reference' },
      { href: '/docs/reference/ports-protocols', label: 'Ports & Protocols' },
      { href: '/docs/reference/glossary', label: 'Glossary' },
    ],
  },
  {
    title: 'Community',
    items: [
      { href: '/docs/community/release-process', label: 'Release Process' },
      { href: '/docs/community/contributing', label: 'Contributing' },
      { href: '/docs/community/security', label: 'Security' },
    ],
  },
];

export function isDocsPathActive(href: string, current: string): boolean {
  return current === href || (href !== '/docs' && current.startsWith(`${href}/`));
}
