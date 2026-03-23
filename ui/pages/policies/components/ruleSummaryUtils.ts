import type { PolicyRule } from '../../../types';

/**
 * Builds a compact human-readable summary of a rule's match target for display
 * in the collapsed rule row. E.g. "tcp → *.github.com :443"
 */
export function buildRuleSummary(rule: PolicyRule): string {
  const proto = rule.match.proto || 'any';

  const dests: string[] = [];
  if (rule.match.dns_hostname) {
    dests.push(rule.match.dns_hostname);
  } else {
    const all = [...(rule.match.dst_cidrs ?? []), ...(rule.match.dst_ips ?? [])];
    if (all.length <= 2) {
      dests.push(...all);
    } else {
      dests.push(...all.slice(0, 2), `+${all.length - 2} more`);
    }
  }

  const dest = dests.length ? dests.join(', ') : '*';
  const ports = rule.match.dst_ports?.length ? `:${rule.match.dst_ports.join(', ')}` : '';

  return `${proto} → ${dest}${ports}`;
}
