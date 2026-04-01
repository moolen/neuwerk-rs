import type { PolicyCreateRequest, PolicySourceGroup } from '../../../types';
import { sanitizeRule } from './rules';
import { sanitizeSources } from './sources';

export function sanitizePolicyRequestForApi(value: PolicyCreateRequest): PolicyCreateRequest {
  const out: PolicyCreateRequest = {
    ...(value.name?.trim() ? { name: value.name.trim() } : {}),
    mode: value.mode,
    policy: {
      source_groups: [],
    },
  };

  if (value.policy.default_policy) {
    out.policy.default_policy = value.policy.default_policy;
  }

  for (const group of value.policy.source_groups ?? []) {
    const normalizedGroup: PolicySourceGroup = {
      id: group.id.trim(),
      mode: group.mode,
      sources: sanitizeSources(group.sources),
      rules: (group.rules ?? []).map((rule) => sanitizeRule(rule)),
    };
    if (typeof group.priority === 'number') normalizedGroup.priority = group.priority;
    if (group.default_action) normalizedGroup.default_action = group.default_action;
    out.policy.source_groups.push(normalizedGroup);
  }

  return out;
}
