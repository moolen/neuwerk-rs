import type { PolicyCreateRequest } from '../types';
import {
  createEmptyPolicyRequest,
  createEmptyRule,
  createEmptySourceGroup,
  createRuleTemplate,
} from './policyModel/factories';
import { nextNamedId } from './policyModel/ids';
import {
  normalizePolicyConfig,
  normalizePolicyRequest,
} from './policyModel/normalize';
import { sanitizePolicyRequestForApi } from './policyModel/sanitize';

export function clonePolicyRequest(value: PolicyCreateRequest): PolicyCreateRequest {
  return JSON.parse(JSON.stringify(value)) as PolicyCreateRequest;
}

export {
  createEmptyPolicyRequest,
  createEmptyRule,
  createEmptySourceGroup,
  createRuleTemplate,
  nextNamedId,
  normalizePolicyConfig,
  normalizePolicyRequest,
  sanitizePolicyRequestForApi,
};
