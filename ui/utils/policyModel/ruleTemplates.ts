import type { PolicyRule } from '../../types';

export type PolicyRuleTemplate = 'dns_allow' | 'l4_allow' | 'tls_metadata' | 'tls_intercept';

export function createRuleFromTemplate(template: PolicyRuleTemplate, id: string): PolicyRule {
  switch (template) {
    case 'dns_allow':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          dns_hostname: '^api\\.example\\.com$',
          src_ports: [],
          dst_ports: [],
          icmp_types: [],
          icmp_codes: [],
        },
      };
    case 'l4_allow':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: ['0.0.0.0/0'],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
        },
      };
    case 'tls_metadata':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
          tls: {
            mode: 'metadata',
            sni: { exact: ['api.example.com'] },
            server_san: { exact: ['api.example.com'] },
            fingerprint_sha256: [],
            trust_anchors_pem: [],
            tls13_uninspectable: 'deny',
          },
        },
      };
    case 'tls_intercept':
      return {
        id,
        action: 'allow',
        mode: 'enforce',
        match: {
          dst_cidrs: [],
          dst_ips: [],
          proto: 'tcp',
          src_ports: [],
          dst_ports: ['443'],
          icmp_types: [],
          icmp_codes: [],
          tls: {
            mode: 'intercept',
            tls13_uninspectable: 'deny',
            fingerprint_sha256: [],
            trust_anchors_pem: [],
            http: {
              request: {
                host: { exact: ['api.example.com'] },
                methods: ['GET'],
                path: { exact: [], prefix: ['/v1/'] },
              },
            },
          },
        },
      };
  }
}
