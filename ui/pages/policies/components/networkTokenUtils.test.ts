import { describe, expect, it } from 'vitest';

import {
  commitNetworkToken,
  validateIpv4AddressToken,
  validateIpv4CidrToken,
} from './networkTokenUtils';

describe('networkTokenUtils', () => {
  it('adds a trimmed valid IPv4 CIDR token', () => {
    expect(commitNetworkToken(' 10.0.0.0/24 ', [], validateIpv4CidrToken)).toEqual({
      added: true,
      error: undefined,
      nextTokens: ['10.0.0.0/24'],
    });
  });

  it('rejects an invalid IPv4 CIDR token', () => {
    expect(commitNetworkToken('10.0.0.1/99', [], validateIpv4CidrToken)).toEqual({
      added: false,
      error: 'Enter a valid IPv4 CIDR',
      nextTokens: [],
    });
  });

  it('adds a valid IPv4 token once and ignores duplicates', () => {
    expect(commitNetworkToken('192.168.178.76', [], validateIpv4AddressToken)).toEqual({
      added: true,
      error: undefined,
      nextTokens: ['192.168.178.76'],
    });
    expect(
      commitNetworkToken('192.168.178.76', ['192.168.178.76'], validateIpv4AddressToken)
    ).toEqual({
      added: false,
      error: undefined,
      nextTokens: ['192.168.178.76'],
    });
  });
});
