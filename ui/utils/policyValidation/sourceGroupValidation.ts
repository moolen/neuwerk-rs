import type { PolicySourceGroup } from '../../types';

interface ValidationIssueLike {
  path: string;
  message: string;
}

export function validateSourceGroup(
  group: PolicySourceGroup,
  groupPath: string,
  integrationNames: Set<string>,
  issues: ValidationIssueLike[]
) {
  if (!group.id.trim()) {
    issues.push({ path: `${groupPath}.id`, message: 'Source group id is required' });
  }
  if (typeof group.priority === 'number' && group.priority < 0) {
    issues.push({ path: `${groupPath}.priority`, message: 'Priority must be >= 0' });
  }
  if (group.default_action && !['allow', 'deny'].includes(group.default_action)) {
    issues.push({ path: `${groupPath}.default_action`, message: 'Default action must be allow or deny' });
  }

  const cidrs = (group.sources?.cidrs ?? []).map((entry) => entry.trim()).filter(Boolean);
  const ips = (group.sources?.ips ?? []).map((entry) => entry.trim()).filter(Boolean);
  const k8s = group.sources?.kubernetes ?? [];
  if (!cidrs.length && !ips.length && !k8s.length) {
    issues.push({
      path: `${groupPath}.sources`,
      message: 'At least one source is required (cidr, ip, or kubernetes selector)',
    });
  }

  for (let si = 0; si < k8s.length; si += 1) {
    const source = k8s[si];
    const sourcePath = `${groupPath}.sources.kubernetes[${si}]`;
    const integration = source.integration.trim();
    if (!integration) {
      issues.push({
        path: `${sourcePath}.integration`,
        message: 'Kubernetes integration is required',
      });
    } else if (integrationNames.size > 0 && !integrationNames.has(integration)) {
      issues.push({
        path: `${sourcePath}.integration`,
        message: `Unknown kubernetes integration: ${integration}`,
      });
    }

    const hasPod = !!source.pod_selector;
    const hasNode = !!source.node_selector;
    if (hasPod === hasNode) {
      issues.push({
        path: sourcePath,
        message: 'Set exactly one of pod selector or node selector',
      });
    }
    if (source.pod_selector) {
      if (!source.pod_selector.namespace.trim()) {
        issues.push({
          path: `${sourcePath}.pod_selector.namespace`,
          message: 'Namespace is required for pod selector',
        });
      }
      for (const [k, v] of Object.entries(source.pod_selector.match_labels ?? {})) {
        if (!k.trim() || !v.trim()) {
          issues.push({
            path: `${sourcePath}.pod_selector.match_labels`,
            message: 'Label keys and values must be non-empty',
          });
          break;
        }
      }
    }
    if (source.node_selector) {
      for (const [k, v] of Object.entries(source.node_selector.match_labels ?? {})) {
        if (!k.trim() || !v.trim()) {
          issues.push({
            path: `${sourcePath}.node_selector.match_labels`,
            message: 'Label keys and values must be non-empty',
          });
          break;
        }
      }
    }
  }
}
