export type NetworkTokenValidator = (value: string) => string | null;

interface CommitNetworkTokenResult {
  added: boolean;
  error?: string;
  nextTokens: string[];
}

function isValidIpv4Octet(value: string): boolean {
  if (!/^\d+$/.test(value)) {
    return false;
  }
  const octet = Number(value);
  return Number.isInteger(octet) && octet >= 0 && octet <= 255;
}

export function isValidIpv4Address(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(isValidIpv4Octet);
}

export function isValidIpv4Cidr(value: string): boolean {
  const [ip, prefix, ...rest] = value.split('/');
  if (rest.length > 0 || !ip || !prefix || !isValidIpv4Address(ip)) {
    return false;
  }
  if (!/^\d+$/.test(prefix)) {
    return false;
  }
  const bits = Number(prefix);
  return Number.isInteger(bits) && bits >= 0 && bits <= 32;
}

export function validateIpv4AddressToken(value: string): string | null {
  return isValidIpv4Address(value) ? null : 'Enter a valid IPv4 address';
}

export function validateIpv4CidrToken(value: string): string | null {
  return isValidIpv4Cidr(value) ? null : 'Enter a valid IPv4 CIDR';
}

export function commitNetworkToken(
  rawValue: string,
  tokens: string[],
  validator: NetworkTokenValidator,
): CommitNetworkTokenResult {
  const value = rawValue.trim();
  if (!value) {
    return {
      added: false,
      nextTokens: tokens,
    };
  }

  const error = validator(value);
  if (error) {
    return {
      added: false,
      error,
      nextTokens: tokens,
    };
  }

  if (tokens.includes(value)) {
    return {
      added: false,
      nextTokens: tokens,
    };
  }

  return {
    added: true,
    nextTokens: [...tokens, value],
  };
}
