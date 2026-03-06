import { describe, expect, it } from 'vitest';

import type { PolicyCreateRequest } from '../../../types';
import { mutateKubernetesSource } from './kubernetesSourceDraft';

function makeDraft(withSource = true): PolicyCreateRequest {
  return {
    mode: 'enforce',
    policy: {
      default_action: 'allow',
      source_groups: [
        {
          id: 'g1',
          priority: 100,
          default_action: 'allow',
          sources: {
            cidrs: ['10.0.0.0/24'],
            ips: [],
            kubernetes: withSource
              ? [
                  {
                    integration: 'k8s',
                    pod_selector: { namespace: 'default', match_labels: {} },
                  },
                ]
              : [],
          },
          rules: [],
        },
      ],
    },
  };
}

describe('kubernetesSourceDraft', () => {
  it('mutates an existing kubernetes source', () => {
    const draft = makeDraft(true);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    mutateKubernetesSource(updateDraft, 0, 0, (source) => {
      source.integration = 'k8s-alt';
    });

    expect(draft.policy.source_groups[0].sources.kubernetes[0].integration).toBe('k8s-alt');
  });

  it('is a no-op for missing source entries', () => {
    const draft = makeDraft(false);
    const updateDraft = (mutator: (next: PolicyCreateRequest) => void) => mutator(draft);

    expect(() =>
      mutateKubernetesSource(updateDraft, 0, 0, (source) => {
        source.integration = 'unused';
      })
    ).not.toThrow();
  });
});
