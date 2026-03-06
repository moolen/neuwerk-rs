import type { PolicyRuleMatch } from '../../../types';

export type RuleMatchProtocolSelection = 'any' | 'tcp' | 'udp' | 'icmp' | 'custom';

export function applyRuleMatchProtoSelection(
  match: PolicyRuleMatch,
  selection: RuleMatchProtocolSelection,
  currentCustom: string
): void {
  if (selection === 'custom') {
    match.proto = currentCustom || '6';
    return;
  }
  if (selection === 'any') {
    delete match.proto;
    return;
  }
  match.proto = selection;
}

export function normalizeRuleMatchDnsHostname(value: string): string | undefined {
  return value.trim() ? value : undefined;
}
