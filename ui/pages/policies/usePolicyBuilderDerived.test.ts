import { describe, expect, it } from 'vitest';

import type { IntegrationView, PolicyCreateRequest } from '../../types';
import {
  collectIntegrationNames,
  derivePolicyValidationIssues,
} from './usePolicyBuilderDerived';

describe('usePolicyBuilderDerived helpers', () => {
  it('collects unique integration names', () => {
    const integrations = [
      { name: 'k8s-a', kind: 'kubernetes' },
      { name: 'k8s-a', kind: 'kubernetes' },
      { name: 'k8s-b', kind: 'kubernetes' },
    ] as IntegrationView[];

    const names = collectIntegrationNames(integrations);
    expect(Array.from(names).sort()).toEqual(['k8s-a', 'k8s-b']);
  });

  it('derives validation issues with provided integration names', () => {
    const draft: PolicyCreateRequest = {
      mode: 'enforce',
      policy: {
        source_groups: [
          {
            id: 'g1',
            sources: {
              cidrs: [],
              ips: [],
              kubernetes: [{ integration: 'missing', pod_selector: undefined, node_selector: undefined }],
            },
            rules: [
              {
                id: 'r1',
                action: 'allow',
                match: {
                  dst_cidrs: [],
                  dst_ips: [],
                  src_ports: [],
                  dst_ports: [],
                  icmp_types: [],
                  icmp_codes: [],
                },
              },
            ],
          },
        ],
      },
    };

    const issues = derivePolicyValidationIssues(draft, new Set(['k8s-a']));
    expect(issues.some((issue) => issue.path.includes('integration'))).toBe(true);
  });
});
