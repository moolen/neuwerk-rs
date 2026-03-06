export function policyEditorSubtitle(
  editorMode: 'create' | 'edit',
  editorTargetId: string | null,
): string {
  if (editorMode === 'create') {
    return 'Creating a new policy';
  }
  return `Editing ${editorTargetId ? editorTargetId.slice(0, 8) : 'policy'}`;
}

export function isPolicySaveDisabled(saving: boolean, issueCount: number): boolean {
  return saving || issueCount > 0;
}
