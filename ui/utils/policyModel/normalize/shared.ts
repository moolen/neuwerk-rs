import type {
  PolicyAction,
  PolicyMode,
  PolicyTls13Uninspectable,
  PolicyTlsMode,
} from '../../../types';

const POLICY_ACTIONS: PolicyAction[] = ['allow', 'deny'];
const POLICY_MODES: PolicyMode[] = ['disabled', 'audit', 'enforce'];
const RULE_MODES = ['audit', 'enforce'] as const;
const TLS_MODES: PolicyTlsMode[] = ['metadata', 'intercept'];
const TLS13_MODES: PolicyTls13Uninspectable[] = ['allow', 'deny'];

export function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
}

export function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.floor(value);
  if (typeof value === 'string' && value.trim().length) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.floor(parsed);
  }
  return undefined;
}

export function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === 'number' ? String(item) : item))
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function asNumberList(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => asNumber(item))
    .filter((item): item is number => typeof item === 'number');
}

export function asStringMap(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    const key = k.trim();
    const val = asString(v);
    if (!key || !val) continue;
    out[key] = val;
  }
  return out;
}

export function asStringListMap(value: unknown): Record<string, string[]> {
  if (!isObject(value)) return {};
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(value)) {
    const key = k.trim();
    if (!key) continue;
    const vals = asStringList(v);
    if (!vals.length) continue;
    out[key] = vals;
  }
  return out;
}

export function asPolicyAction(value: unknown, fallback: PolicyAction = 'deny'): PolicyAction {
  const parsed = asString(value)?.toLowerCase();
  return POLICY_ACTIONS.includes(parsed as PolicyAction) ? (parsed as PolicyAction) : fallback;
}

export function asPolicyMode(value: unknown, fallback: PolicyMode = 'enforce'): PolicyMode {
  const parsed = asString(value)?.toLowerCase();
  return POLICY_MODES.includes(parsed as PolicyMode) ? (parsed as PolicyMode) : fallback;
}

export function asRuleMode(value: unknown): 'audit' | 'enforce' {
  const parsed = asString(value)?.toLowerCase();
  return RULE_MODES.includes(parsed as (typeof RULE_MODES)[number])
    ? (parsed as 'audit' | 'enforce')
    : 'enforce';
}

export function asTlsMode(value: unknown): PolicyTlsMode {
  const parsed = asString(value)?.toLowerCase();
  return TLS_MODES.includes(parsed as PolicyTlsMode) ? (parsed as PolicyTlsMode) : 'metadata';
}

export function asTls13Mode(value: unknown): PolicyTls13Uninspectable {
  const parsed = asString(value)?.toLowerCase();
  return TLS13_MODES.includes(parsed as PolicyTls13Uninspectable)
    ? (parsed as PolicyTls13Uninspectable)
    : 'deny';
}

export function sanitizeOptionalNumber(value: unknown): number | undefined {
  const n = asNumber(value);
  if (typeof n !== 'number' || n < 0) return undefined;
  return n;
}
