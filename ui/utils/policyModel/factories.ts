import type {
  PolicyCreateRequest,
  PolicyRule,
  PolicySourceGroup,
} from '../../types';
import { createRuleFromTemplate, type PolicyRuleTemplate } from './ruleTemplates';

export function createEmptyRule(id = 'rule-1'): PolicyRule {
  return {
    id,
    action: 'allow',
    mode: 'enforce',
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
    id,
    priority: 0,
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
