import { describe, expect, it } from 'vitest';

import type { PolicySourceGroup } from '../../../types';
import {
  summarizeGroupAction,
  summarizeRulePills,
  summarizeSourceIdentity,
} from './policySourceGroupTableHelpers';

describe('policySourceGroupTableHelpers', () => {
  it('summarizes source identity, action, and rule pills for mixed groups', () => {
    const group: PolicySourceGroup = {
      id: 'apps',
      sources: {
        cidrs: ['10.0.0.0/24'],
        ips: ['192.168.1.10'],
        kubernetes: [],
      },
      rules: [
        {
          id: 'allow-web',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['443', '80'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
        {
          id: 'deny-dns',
          action: 'deny',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'blocked.example',
            proto: 'udp',
            src_ports: [],
            dst_ports: ['53'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
      ],
    };

    expect(summarizeSourceIdentity(group)).toEqual({
      primary: 'apps',
      secondary: ['10.0.0.0/24', '192.168.1.10'],
    });
    expect(summarizeGroupAction(group)).toBe('mixed');
    expect(summarizeRulePills(group)).toContain('TCP:443,80');
  });

  it('includes compact kubernetes descriptors in secondary source identity', () => {
    const group: PolicySourceGroup = {
      id: 'k8s-workloads',
      sources: {
        cidrs: [],
        ips: [],
        kubernetes: [
          {
            integration: 'cluster-a',
            pod_selector: {
              namespace: 'payments',
              match_labels: { app: 'api', tier: 'backend' },
            },
          },
          {
            integration: 'cluster-b',
            node_selector: {
              match_labels: { role: 'edge' },
            },
          },
          {
            integration: 'cluster-c',
          },
        ],
      },
      rules: [],
    };

    expect(summarizeSourceIdentity(group)).toEqual({
      primary: 'k8s-workloads',
      secondary: [
        'k8s:cluster-a pod:payments app=api,tier=backend',
        'k8s:cluster-b node role=edge',
        'k8s:cluster-c',
      ],
    });
  });
});
