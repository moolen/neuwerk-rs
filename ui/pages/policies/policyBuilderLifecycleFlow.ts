import { buildHandleDelete } from './policyBuilderLifecycleDelete';
import { buildHandleCreate, buildLoadAll, buildLoadEditorForPolicy } from './policyBuilderLifecycleLoad';
import { buildHandleSave } from './policyBuilderLifecycleSave';
import type { PolicyBuilderLifecycleDeps, PolicyBuilderLifecycleHandlers } from './policyBuilderTypes';

export function createPolicyBuilderLifecycleHandlers(
  deps: PolicyBuilderLifecycleDeps,
): PolicyBuilderLifecycleHandlers {
  const handleCreate = buildHandleCreate(deps);
  const loadEditorForPolicy = buildLoadEditorForPolicy(deps);
  const loadAll = buildLoadAll(deps, handleCreate);
  const handleDelete = buildHandleDelete(deps, loadAll, handleCreate);
  const handleSave = buildHandleSave(deps, loadAll);

  return {
    handleCreate,
    loadEditorForPolicy,
    loadAll,
    handleDelete,
    handleSave,
  };
}
