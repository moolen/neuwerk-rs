import type { PolicySourceGroup } from '../../../types';

export type SourceGroupActionSummary = 'allow' | 'deny' | 'mixed';

function uniqueNonEmpty(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();

  for (const raw of values) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }

  return out;
}

function numericPortOrder(a: string, b: string): number {
  const aNum = Number(a);
  const bNum = Number(b);
  const aIsInt = Number.isInteger(aNum);
  const bIsInt = Number.isInteger(bNum);

  if (aIsInt && bIsInt) return bNum - aNum;
  if (aIsInt) return -1;
  if (bIsInt) return 1;
  return a.localeCompare(b);
}

function summarizeLabels(labels: Record<string, string>): string {
  return Object.entries(labels)
    .filter(([key, value]) => key.trim() && value.trim())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key.trim()}=${value.trim()}`)
    .join(',');
}

function summarizeKubernetesSource(
  source: PolicySourceGroup['sources']['kubernetes'][number],
): string {
  const integration = source.integration.trim();
  const base = `k8s:${integration || 'unknown'}`;

  if (source.pod_selector) {
    const namespace = source.pod_selector.namespace.trim();
    const labels = summarizeLabels(source.pod_selector.match_labels ?? {});
    return labels ? `${base} pod:${namespace || '*'} ${labels}` : `${base} pod:${namespace || '*'}`;
  }

  if (source.node_selector) {
    const labels = summarizeLabels(source.node_selector.match_labels ?? {});
    return labels ? `${base} node ${labels}` : `${base} node`;
  }

  return base;
}

export function summarizeSourceIdentity(
  group: PolicySourceGroup,
): { primary: string; secondary: string[] } {
  return {
    primary: group.id,
    secondary: uniqueNonEmpty([
      ...(group.sources.cidrs ?? []),
      ...(group.sources.ips ?? []),
      ...(group.sources.kubernetes ?? []).map(summarizeKubernetesSource),
    ]),
  };
}

export function summarizeRulePills(group: PolicySourceGroup): string[] {
  const byProto = new Map<string, { ports: string[]; seenPorts: Set<string>; hasPortlessRule: boolean }>();
  const protoOrder: string[] = [];

  for (const rule of group.rules) {
    const proto = (rule.match.proto?.trim() || 'any').toUpperCase();
    let entry = byProto.get(proto);
    if (!entry) {
      entry = { ports: [], seenPorts: new Set<string>(), hasPortlessRule: false };
      byProto.set(proto, entry);
      protoOrder.push(proto);
    }

    const ports = uniqueNonEmpty(rule.match.dst_ports ?? []);
    if (!ports.length) {
      entry.hasPortlessRule = true;
      continue;
    }

    for (const port of ports) {
      if (entry.seenPorts.has(port)) continue;
      entry.seenPorts.add(port);
      entry.ports.push(port);
    }
  }

  return protoOrder.map((proto) => {
    const entry = byProto.get(proto);
    if (!entry || entry.hasPortlessRule || !entry.ports.length) return proto;
    return `${proto}:${entry.ports.slice().sort(numericPortOrder).join(',')}`;
  });
}

export function summarizeGroupAction(group: PolicySourceGroup): SourceGroupActionSummary {
  const hasAllow = group.rules.some((rule) => rule.action === 'allow');
  const hasDeny = group.rules.some((rule) => rule.action === 'deny');

  if (hasAllow && hasDeny) return 'mixed';
  if (hasAllow) return 'allow';
  if (hasDeny) return 'deny';
  if (group.default_action) return group.default_action;
  return 'deny';
}
