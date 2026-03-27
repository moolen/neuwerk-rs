import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRequest, MockRoute } from '../types';

function parsePositiveInteger(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return undefined;
  }
  return Math.floor(parsed);
}

function queryParams(request: MockRequest): URLSearchParams {
  return new URL(request.url, 'http://neuwerk.dev').searchParams;
}

export function createAuditRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/audit/findings',
      handler: (request) => {
        const params = queryParams(request);
        const policyId = params.get('policy_id');
        const findingTypes = new Set(params.getAll('finding_type'));
        const sourceGroups = new Set(params.getAll('source_group'));
        const since = parsePositiveInteger(params.get('since'));
        const until = parsePositiveInteger(params.get('until'));
        const limit = parsePositiveInteger(params.get('limit'));

        const items = state.auditFindings
          .filter((item) => {
            if (policyId && item.policy_id !== policyId) {
              return false;
            }
            if (findingTypes.size > 0 && !findingTypes.has(item.finding_type)) {
              return false;
            }
            if (sourceGroups.size > 0 && !sourceGroups.has(item.source_group)) {
              return false;
            }
            if (typeof since === 'number' && item.last_seen < since) {
              return false;
            }
            if (typeof until === 'number' && item.first_seen > until) {
              return false;
            }
            return true;
          })
          .sort((left, right) => right.last_seen - left.last_seen);

        return jsonResponse({
          items: typeof limit === 'number' ? items.slice(0, limit) : items,
          partial: false,
          node_errors: [],
          nodes_queried: state.stats.cluster.node_count,
          nodes_responded: state.stats.cluster.node_count,
        });
      },
    },
  ];
}
