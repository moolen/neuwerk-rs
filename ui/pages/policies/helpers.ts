export const RULE_TEMPLATES = [
  { id: 'dns_allow', label: 'DNS allowlist rule' },
  { id: 'l4_allow', label: 'L4 allow rule' },
  { id: 'tls_metadata', label: 'TLS metadata rule' },
  { id: 'tls_intercept', label: 'TLS intercept HTTP rule' },
] as const;

export type RuleTemplateId = (typeof RULE_TEMPLATES)[number]['id'];
export {
  listToText,
  numberListToText,
  parseProtoKind,
  textToList,
  textToNumberList,
} from './valueCodec';
export {
  duplicateId,
  emptyKubernetesSource,
  emptyTlsHeaders,
  emptyTlsNameMatch,
  formatIssues,
  moveItem,
} from './policyDraftHelpers';
