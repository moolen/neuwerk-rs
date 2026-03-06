import type {
  PolicyKubernetesNodeSelector,
  PolicyKubernetesPodSelector,
  PolicyKubernetesSource,
  PolicySources,
} from '../../../types';
import { asString, asStringList, asStringMap, isObject } from './shared';

function normalizeKubernetesPodSelector(value: unknown): PolicyKubernetesPodSelector | undefined {
  if (!isObject(value)) return undefined;
  const namespace = asString(value.namespace) ?? '';
  const match_labels = asStringMap(value.match_labels);
  if (!namespace && !Object.keys(match_labels).length) return undefined;
  return {
    namespace,
    match_labels,
  };
}

function normalizeKubernetesNodeSelector(value: unknown): PolicyKubernetesNodeSelector | undefined {
  if (!isObject(value)) return undefined;
  return {
    match_labels: asStringMap(value.match_labels),
  };
}

function normalizeKubernetesSource(value: unknown): PolicyKubernetesSource | undefined {
  if (!isObject(value)) return undefined;
  const integration = asString(value.integration) ?? '';
  const pod_selector = normalizeKubernetesPodSelector(value.pod_selector);
  const node_selector = normalizeKubernetesNodeSelector(value.node_selector);
  if (!integration && !pod_selector && !node_selector) return undefined;
  return {
    integration,
    ...(pod_selector ? { pod_selector } : {}),
    ...(node_selector ? { node_selector } : {}),
  };
}

export function normalizeSources(value: unknown): PolicySources {
  if (!isObject(value)) return { cidrs: [], ips: [], kubernetes: [] };
  const kubernetes = Array.isArray(value.kubernetes)
    ? value.kubernetes
        .map((entry) => normalizeKubernetesSource(entry))
        .filter((entry): entry is PolicyKubernetesSource => !!entry)
    : [];
  return {
    cidrs: asStringList(value.cidrs),
    ips: asStringList(value.ips),
    kubernetes,
  };
}
