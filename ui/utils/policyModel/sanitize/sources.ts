import type { PolicyKubernetesSource, PolicySources } from '../../../types';
import { sanitizeStringList, sanitizeStringMap } from './shared';

export function sanitizeSources(value: PolicySources | undefined): PolicySources {
  const kubernetes: PolicyKubernetesSource[] = [];

  for (const source of value?.kubernetes ?? []) {
    const integration = source.integration.trim();
    const pod_selector = source.pod_selector
      ? {
          namespace: source.pod_selector.namespace.trim(),
          match_labels: sanitizeStringMap(source.pod_selector.match_labels),
        }
      : undefined;
    const node_selector = source.node_selector
      ? {
          match_labels: sanitizeStringMap(source.node_selector.match_labels),
        }
      : undefined;

    if (!integration && !pod_selector && !node_selector) continue;
    const normalizedSource: PolicyKubernetesSource = { integration };
    if (pod_selector) normalizedSource.pod_selector = pod_selector;
    if (node_selector) normalizedSource.node_selector = node_selector;
    kubernetes.push(normalizedSource);
  }

  return {
    cidrs: sanitizeStringList(value?.cidrs),
    ips: sanitizeStringList(value?.ips),
    kubernetes,
  };
}
