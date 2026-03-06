import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../types';
import { validatePolicyRequest } from './policyValidation';

function buildBaseRequest(): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      source_groups: [
        {
          id: 'internal',
          sources: {
            cidrs: ['10.0.0.0/24'],
            ips: [],
            kubernetes: [],
          },
          rules: [
            {
              id: 'allow-web',
              action: 'allow',
              match: {
                dst_cidrs: [],
                dst_ips: [],
                proto: 'tcp',
                src_ports: [],
                dst_ports: ['443'],
                icmp_types: [],
                icmp_codes: [],
              },
            },
          ],
        },
      ],
    },
  };
}

describe('validatePolicyRequest', () => {
  it('flags invalid dns hostname regex', () => {
    const request = buildBaseRequest();
    request.policy.source_groups[0].rules[0].match.dns_hostname = '[';

    const issues = validatePolicyRequest(request);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'policy.source_groups[0].rules[0].match.dns_hostname',
          message: 'dns_hostname must be a valid regex',
        }),
      ])
    );
  });

  it('requires tls.http constraints when tls.mode is intercept', () => {
    const request = buildBaseRequest();
    request.policy.source_groups[0].rules[0].match.tls = {
      mode: 'intercept',
      fingerprint_sha256: [],
      trust_anchors_pem: [],
    };

    const issues = validatePolicyRequest(request);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'policy.source_groups[0].rules[0].match.tls',
          message: 'tls.mode intercept requires tls.http constraints',
        }),
      ])
    );
  });
});
