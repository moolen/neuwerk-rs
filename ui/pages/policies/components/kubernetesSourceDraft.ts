import type { PolicyCreateRequest, PolicyKubernetesSource } from '../../../types';
import type { UpdateDraft } from './formTypes';

export function mutateKubernetesSource(
  updateDraft: UpdateDraft,
  groupIndex: number,
  sourceIndex: number,
  mutator: (source: PolicyKubernetesSource) => void
): void {
  updateDraft((next: PolicyCreateRequest) => {
    const source = next.policy.source_groups[groupIndex]?.sources.kubernetes?.[sourceIndex];
    if (!source) {
      return;
    }
    mutator(source);
  });
}
