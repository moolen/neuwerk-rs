import { describe, expect, it } from 'vitest';

import { createEmptyPolicyRequest, createEmptySourceGroup } from '../../../utils/policyModel';
import {
  setSourceGroupDefaultAction,
  setSourceGroupId,
  setSourceGroupMode,
  setSourceGroupPriority,
} from './sourceGroupHeaderDraft';

function buildDraft() {
  const draft = createEmptyPolicyRequest();
  draft.policy.source_groups.push(createEmptySourceGroup('group-1'));
  return draft;
}

describe('sourceGroupHeaderDraft', () => {
  it('updates source-group id', () => {
    const draft = buildDraft();
    setSourceGroupId(draft, 0, 'new-id');
    expect(draft.policy.source_groups[0].id).toBe('new-id');
  });

  it('updates source-group priority and supports clearing', () => {
    const draft = buildDraft();
    setSourceGroupPriority(draft, 0, '7');
    expect(draft.policy.source_groups[0].priority).toBe(7);
    setSourceGroupPriority(draft, 0, '   ');
    expect(draft.policy.source_groups[0].priority).toBeUndefined();
  });

  it('updates source-group default action', () => {
    const draft = buildDraft();
    setSourceGroupDefaultAction(draft, 0, 'allow');
    expect(draft.policy.source_groups[0].default_action).toBe('allow');
  });

  it('updates source-group mode', () => {
    const draft = buildDraft();
    setSourceGroupMode(draft, 0, 'audit');
    expect(draft.policy.source_groups[0].mode).toBe('audit');
  });

  it('no-ops when group index is out-of-range', () => {
    const draft = buildDraft();
    setSourceGroupId(draft, 3, 'x');
    setSourceGroupPriority(draft, 3, '9');
    setSourceGroupDefaultAction(draft, 3, 'allow');
    setSourceGroupMode(draft, 3, 'audit');
    expect(draft.policy.source_groups[0].id).toBe('group-1');
    expect(draft.policy.source_groups[0].priority).toBe(0);
    expect(draft.policy.source_groups[0].default_action).toBe('deny');
    expect(draft.policy.source_groups[0].mode).toBe('enforce');
  });
});
