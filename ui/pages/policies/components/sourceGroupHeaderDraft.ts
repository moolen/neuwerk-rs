import type { PolicyCreateRequest } from '../../../types';

export function setSourceGroupId(
  draft: PolicyCreateRequest,
  groupIndex: number,
  value: string,
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) return;
  group.id = value;
}

export function setSourceGroupPriority(
  draft: PolicyCreateRequest,
  groupIndex: number,
  value: string,
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) return;
  const priority = value.trim();
  group.priority = priority === '' ? undefined : Number(priority);
}

export function setSourceGroupDefaultAction(
  draft: PolicyCreateRequest,
  groupIndex: number,
  value: 'allow' | 'deny',
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) return;
  group.default_action = value;
}

export function setSourceGroupMode(
  draft: PolicyCreateRequest,
  groupIndex: number,
  value: 'audit' | 'enforce',
): void {
  const group = draft.policy.source_groups[groupIndex];
  if (!group) return;
  group.mode = value;
}
