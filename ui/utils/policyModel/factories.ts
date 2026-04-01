import type {
  PolicyCreateRequest,
  PolicyRule,
  PolicySourceGroup,
} from '../../types';
import { createRuleFromTemplate, type PolicyRuleTemplate } from './ruleTemplates';

let nextSourceGroupClientKey = 1;

export function createSourceGroupClientKey(seed = 'group'): string {
  const normalizedSeed = seed.trim() || 'group';
  const key = `${normalizedSeed}-${nextSourceGroupClientKey}`;
  nextSourceGroupClientKey += 1;
  return key;
}

export function createEmptyRule(id = 'rule-1'): PolicyRule {
  return {
    id,
    action: 'allow',
    match: {
      dst_cidrs: [],
      dst_ips: [],
      src_ports: [],
      dst_ports: [],
      icmp_types: [],
      icmp_codes: [],
    },
  };
}

export function createRuleTemplate(
  template: PolicyRuleTemplate,
  id: string
): PolicyRule {
  return createRuleFromTemplate(template, id);
}

export function createEmptySourceGroup(id = 'group-1'): PolicySourceGroup {
  return {
    client_key: createSourceGroupClientKey(id),
    id,
    priority: 0,
    mode: 'enforce',
    sources: {
      cidrs: [],
      ips: [],
      kubernetes: [],
    },
    rules: [],
    default_action: 'deny',
  };
}

export function createEmptyPolicyRequest(): PolicyCreateRequest {
  return {
    name: '',
    mode: 'enforce',
    policy: {
      default_policy: 'deny',
      source_groups: [],
    },
  };
}
