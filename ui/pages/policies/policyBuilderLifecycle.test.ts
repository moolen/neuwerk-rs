import { describe, expect, it } from 'vitest';

import type { PolicyRecord } from '../../types';
import { deriveLoadAllFollowUp, errorMessage } from './policyBuilderLifecycle';

describe('policyBuilderLifecycle helpers', () => {
  it('derives initial load follow-up action', () => {
    const policies = [{ id: 'p-1' }, { id: 'p-2' }] as PolicyRecord[];
    expect(deriveLoadAllFollowUp(policies, null)).toEqual({ kind: 'open-first', policyId: 'p-1' });
    expect(deriveLoadAllFollowUp(policies, 'p-2')).toEqual({ kind: 'none' });
    expect(deriveLoadAllFollowUp([], null)).toEqual({ kind: 'create' });
  });

  it('normalizes unknown errors to fallback message', () => {
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('boom');
    expect(errorMessage('x', 'fallback')).toBe('fallback');
  });
});
