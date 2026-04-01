import type { PolicyConfig, PolicyCreateRequest } from '../../types';
import { createEmptyPolicyRequest } from './factories';
import { normalizeSourceGroup } from './normalize/rules';
import { asPolicyAction, asPolicyMode, asString, isObject } from './normalize/shared';

export function normalizePolicyConfig(value: unknown): PolicyConfig {
  if (!isObject(value)) {
    return {
      default_policy: 'deny',
      source_groups: [],
    };
  }
  const source_groups = Array.isArray(value.source_groups)
    ? value.source_groups.map((entry, idx) => normalizeSourceGroup(entry, idx))
    : [];
  const defaultPolicy = asString(value.default_policy);
  return {
    ...(defaultPolicy ? { default_policy: asPolicyAction(defaultPolicy) } : {}),
    source_groups,
  };
}

export function normalizePolicyRequest(value: unknown): PolicyCreateRequest {
  if (!isObject(value)) {
    return createEmptyPolicyRequest();
  }
  const policyValue = isObject(value.policy) ? value.policy : value;
  return {
    ...(asString(value.name) ? { name: asString(value.name) } : {}),
    mode: asPolicyMode(value.mode),
    policy: normalizePolicyConfig(policyValue),
  };
}
