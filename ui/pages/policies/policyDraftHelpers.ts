import type {
  PolicyKubernetesSource,
  PolicyTlsHttpHeadersMatch,
  PolicyTlsNameMatch,
} from '../../types';
import { nextNamedId } from '../../utils/policyModel';
import type { PolicyValidationIssue } from '../../utils/policyValidation';

export function emptyTlsNameMatch(): PolicyTlsNameMatch {
  return {
    exact: [],
  };
}

export function emptyTlsHeaders(): PolicyTlsHttpHeadersMatch {
  return {
    require_present: [],
    deny_present: [],
    exact: {},
    regex: {},
  };
}

export function emptyKubernetesSource(): PolicyKubernetesSource {
  return {
    integration: '',
    pod_selector: {
      namespace: '',
      match_labels: {},
    },
  };
}

export function moveItem<T>(items: T[], index: number, direction: -1 | 1): T[] {
  const nextIndex = index + direction;
  if (nextIndex < 0 || nextIndex >= items.length) return items;
  const next = [...items];
  const [item] = next.splice(index, 1);
  next.splice(nextIndex, 0, item);
  return next;
}

export function duplicateId(base: string, existing: string[]): string {
  const prefix = base.trim().replace(/-\d+$/, '') || 'item';
  return nextNamedId(prefix, existing);
}

export function formatIssues(issues: PolicyValidationIssue[]): string[] {
  return issues.map((issue) => `${issue.path}: ${issue.message}`);
}
