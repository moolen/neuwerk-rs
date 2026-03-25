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

  it('stabilizes protocol/port pills across equivalent split and unsplit rules', () => {
    const combined: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'tcp-combined',
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
      ],
    };

    const split: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'tcp-443',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['443'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
        {
          id: 'tcp-80',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['80'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
      ],
    };

    expect(summarizeRulePills(split)).toEqual(summarizeRulePills(combined));
    expect(summarizeRulePills(split)).toEqual(['TCP:443,80']);
  });

  it('canonicalizes equivalent protocol port sets regardless of encounter order', () => {
    const combined: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'tcp-combined',
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
      ],
    };

    const splitReordered: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'tcp-80',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['80'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
        {
          id: 'tcp-443',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['443'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
      ],
    };

    expect(summarizeRulePills(splitReordered)).toEqual(summarizeRulePills(combined));
    expect(summarizeRulePills(splitReordered)).toEqual(['TCP:443,80']);
  });

  it('canonicalizes protocol ordering across equivalent multi-protocol rule sets', () => {
    const tcpThenUdp: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'tcp-443',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['443'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
        {
          id: 'udp-53',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
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

    const udpThenTcp: PolicySourceGroup = {
      id: 'apps',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [
        {
          id: 'udp-53',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'udp',
            src_ports: [],
            dst_ports: ['53'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
        {
          id: 'tcp-443',
          action: 'allow',
          match: {
            dst_cidrs: [],
            dst_ips: [],
            dns_hostname: 'example.com',
            proto: 'tcp',
            src_ports: [],
            dst_ports: ['443'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
      ],
    };

    expect(summarizeRulePills(udpThenTcp)).toEqual(summarizeRulePills(tcpThenUdp));
    expect(summarizeRulePills(udpThenTcp)).toEqual(['TCP:443', 'UDP:53']);
  });

  it('defaults group action to deny when rules and default_action are both absent', () => {
    const group: PolicySourceGroup = {
      id: 'empty',
      sources: { cidrs: [], ips: [], kubernetes: [] },
      rules: [],
    };

    expect(summarizeGroupAction(group)).toBe('deny');
  });

  it('marks action as mixed when rules and default_action produce both outcomes', () => {
    const group: PolicySourceGroup = {
      id: 'default-deny-with-allow-exception',
      default_action: 'deny',
      sources: { cidrs: [], ips: [], kubernetes: [] },
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
            dst_ports: ['443'],
            icmp_types: [],
            icmp_codes: [],
            tls: null,
          },
        },
      ],
    };

    expect(summarizeGroupAction(group)).toBe('mixed');
  });
});
