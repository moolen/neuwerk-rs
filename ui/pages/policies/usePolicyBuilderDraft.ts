import type { Dispatch, SetStateAction } from 'react';

import type { PolicyCreateRequest } from '../../types';
import { clonePolicyRequest } from '../../utils/policyModel';

export function createUpdateDraft(
  setDraft: Dispatch<SetStateAction<PolicyCreateRequest>>,
): (mutator: (next: PolicyCreateRequest) => void) => void {
  return (mutator) => {
    setDraft((prev) => {
      const next = clonePolicyRequest(prev);
      mutator(next);
      return next;
    });
  };
}
