import type { PolicyRuleMatch } from '../../../types';
import { isValidRegex } from '../tlsHttpValidation';
import type { ValidationIssueLike } from './types';

function isValidPortSpec(value: string): boolean {
  const trimmed = value.trim();
  const match = /^(\d{1,5})(\s*-\s*(\d{1,5}))?$/.exec(trimmed);
  if (!match) return false;
  const start = Number(match[1]);
  const end = match[3] ? Number(match[3]) : start;
  if (!Number.isInteger(start) || !Number.isInteger(end)) return false;
  if (start < 1 || start > 65535 || end < 1 || end > 65535) return false;
  return start <= end;
}

function isValidProto(value?: string): boolean {
  if (!value) return true;
  const proto = value.trim().toLowerCase();
  if (!proto) return true;
  if (proto === 'any' || proto === 'tcp' || proto === 'udp' || proto === 'icmp') return true;
  if (!/^\d+$/.test(proto)) return false;
  const n = Number(proto);
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

function protoValue(value?: string): string {
  return (value ?? 'any').trim().toLowerCase() || 'any';
}

export function validateRuleMatchCore(
  match: PolicyRuleMatch,
  rulePath: string,
  issues: ValidationIssueLike[]
): string {
  const proto = protoValue(match.proto);
  if (!isValidProto(match.proto)) {
    issues.push({ path: `${rulePath}.match.proto`, message: 'Protocol must be any/tcp/udp/icmp or 0-255' });
  }

  if (match.dns_hostname !== undefined) {
    const dns = match.dns_hostname.trim();
    if (!dns) {
      issues.push({ path: `${rulePath}.match.dns_hostname`, message: 'dns_hostname cannot be empty' });
    } else if (!isValidRegex(dns)) {
      issues.push({ path: `${rulePath}.match.dns_hostname`, message: 'dns_hostname must be a valid regex' });
    }
  }

  for (let index = 0; index < (match.src_ports ?? []).length; index += 1) {
    if (!isValidPortSpec(match.src_ports[index])) {
      issues.push({
        path: `${rulePath}.match.src_ports[${index}]`,
        message: 'Invalid port spec (use 1-65535 or start-end)',
      });
    }
  }

  for (let index = 0; index < (match.dst_ports ?? []).length; index += 1) {
    if (!isValidPortSpec(match.dst_ports[index])) {
      issues.push({
        path: `${rulePath}.match.dst_ports[${index}]`,
        message: 'Invalid port spec (use 1-65535 or start-end)',
      });
    }
  }

  if (proto === 'icmp' && ((match.src_ports ?? []).length || (match.dst_ports ?? []).length)) {
    issues.push({
      path: `${rulePath}.match`,
      message: 'ICMP rules cannot include src/dst port constraints',
    });
  }

  if (((match.icmp_types ?? []).length || (match.icmp_codes ?? []).length) && proto !== 'icmp' && proto !== 'any') {
    issues.push({
      path: `${rulePath}.match`,
      message: 'ICMP type/code requires proto icmp or any',
    });
  }

  for (let index = 0; index < (match.icmp_types ?? []).length; index += 1) {
    const value = match.icmp_types[index];
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      issues.push({
        path: `${rulePath}.match.icmp_types[${index}]`,
        message: 'ICMP types must be integers between 0 and 255',
      });
    }
  }
  for (let index = 0; index < (match.icmp_codes ?? []).length; index += 1) {
    const value = match.icmp_codes[index];
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      issues.push({
        path: `${rulePath}.match.icmp_codes[${index}]`,
        message: 'ICMP codes must be integers between 0 and 255',
      });
    }
  }

  return proto;
}
