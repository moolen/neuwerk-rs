import type { PolicyRecord } from '../../../types';

const MAX_SUMMARY_ITEMS = 3;

function uniqueNonEmpty(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function summarizeValues(values: string[], emptyLabel: string): string {
  if (!values.length) return emptyLabel;
  if (values.length <= MAX_SUMMARY_ITEMS) return values.join(', ');
  return `${values.slice(0, MAX_SUMMARY_ITEMS).join(', ')} +${values.length - MAX_SUMMARY_ITEMS}`;
}

export function snapshotShortId(id: string): string {
  return id.slice(0, 8);
}

export function policyDisplayName(policy: PolicyRecord): string {
  const name = policy.name?.trim();
  return name && name.length ? name : `Policy ${snapshotShortId(policy.id)}`;
}

export function policyRuleCount(policy: PolicyRecord): number {
  return policy.policy.source_groups.reduce((total, group) => total + group.rules.length, 0);
}

export function policyHasDpi(policy: PolicyRecord): boolean {
  return policy.policy.source_groups.some((group) =>
    group.rules.some((rule) => rule.match.tls?.mode === 'intercept')
  );
}

export function summarizePolicySources(policy: PolicyRecord): string {
  const cidrs = uniqueNonEmpty(
    policy.policy.source_groups.flatMap((group) => group.sources.cidrs ?? [])
  );
  return summarizeValues(cidrs, 'none');
}

export function summarizePolicyDestinations(policy: PolicyRecord): string {
  const values = uniqueNonEmpty(
    policy.policy.source_groups.flatMap((group) =>
      group.rules.flatMap((rule) => [
        ...(rule.match.dns_hostname ? [rule.match.dns_hostname] : []),
        ...(rule.match.dst_cidrs ?? []),
        ...(rule.match.dst_ips ?? []),
      ])
    )
  );
  return summarizeValues(values, 'any');
}
