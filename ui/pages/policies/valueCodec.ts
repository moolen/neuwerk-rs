export function listToText(values: string[]): string {
  return values.join('\n');
}

export function textToList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function numberListToText(values: number[]): string {
  return values.join(', ');
}

export function textToNumberList(value: string): number[] {
  return value
    .split(/[\n,]/)
    .map((entry) => Number(entry.trim()))
    .filter((entry) => Number.isFinite(entry))
    .map((entry) => Math.floor(entry));
}

export function parseProtoKind(proto?: string): {
  kind: 'any' | 'tcp' | 'udp' | 'icmp' | 'custom';
  custom: string;
} {
  const value = (proto ?? '').trim().toLowerCase();
  if (!value || value === 'any') return { kind: 'any', custom: '' };
  if (value === 'tcp') return { kind: 'tcp', custom: '' };
  if (value === 'udp') return { kind: 'udp', custom: '' };
  if (value === 'icmp') return { kind: 'icmp', custom: '' };
  return { kind: 'custom', custom: value };
}
