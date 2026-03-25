import type { PolicyRecord } from '../../types';

export type LoadAllFollowUp =
  | { kind: 'select-first'; policyId: string }
  | { kind: 'create' }
  | { kind: 'none' };

export function deriveLoadAllFollowUp(
  policies: PolicyRecord[],
  selectedId: string | null,
): LoadAllFollowUp {
  if (!policies.length) return { kind: 'create' };
  if (!selectedId) {
    return { kind: 'select-first', policyId: policies[0].id };
  }
  return { kind: 'none' };
}

export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}
