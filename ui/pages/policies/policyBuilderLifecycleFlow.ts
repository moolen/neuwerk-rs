import { buildLoadAll, buildLoadEditorForPolicy } from './policyBuilderLifecycleLoad';
import { buildHandleSave } from './policyBuilderLifecycleSave';
import type { PolicyBuilderLifecycleDeps, PolicyBuilderLifecycleHandlers } from './policyBuilderTypes';

export function createPolicyBuilderLifecycleHandlers(
  deps: PolicyBuilderLifecycleDeps,
): PolicyBuilderLifecycleHandlers {
  const loadEditorForPolicy = buildLoadEditorForPolicy(deps);
  const loadAll = buildLoadAll(deps);
  const handleSave = buildHandleSave(deps, loadAll);

  return {
    loadEditorForPolicy,
    loadAll,
    handleSave,
  };
}
