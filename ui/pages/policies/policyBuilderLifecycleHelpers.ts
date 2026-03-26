import type { PolicyRecord } from '../../types';

export type LoadAllFollowUp =
  | { kind: 'select-first'; policyId: string }
  | { kind: 'create' }
  | { kind: 'none' };

export function deriveLoadAllFollowUp(
  policies: PolicyRecord[],
  selectedPolicyId: string | null,
): LoadAllFollowUp {
  if (!policies.length) return { kind: 'create' };
  if (!selectedPolicyId) {
    return { kind: 'select-first', policyId: policies[0].id };
  }
  return policies.some((policy) => policy.id === selectedPolicyId)
    ? { kind: 'none' }
    : { kind: 'select-first', policyId: policies[0].id };
}

export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}
