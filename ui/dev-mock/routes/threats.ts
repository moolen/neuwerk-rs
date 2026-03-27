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

function parseBoolean(value: string | null): boolean | undefined {
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  return undefined;
}

function queryParams(request: MockRequest): URLSearchParams {
  return new URL(request.url, 'http://neuwerk.dev').searchParams;
}

export function createThreatRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: 'GET',
      pathname: '/api/v1/threats/findings',
      handler: (request) => {
        const params = queryParams(request);
        const indicatorTypes = new Set(params.getAll('indicator_type'));
        const severities = new Set(params.getAll('severity'));
        const sourceGroups = new Set(params.getAll('source_group'));
        const observationLayers = new Set(params.getAll('observation_layer'));
        const feeds = new Set(params.getAll('feed'));
        const matchSources = new Set(params.getAll('match_source'));
        const alertable = parseBoolean(params.get('alertable'));
        const since = parsePositiveInteger(params.get('since'));
        const until = parsePositiveInteger(params.get('until'));
        const limit = parsePositiveInteger(params.get('limit'));

        const items = state.threatFindings
          .filter((item) => {
            if (indicatorTypes.size > 0 && !indicatorTypes.has(item.indicator_type)) {
              return false;
            }
            if (severities.size > 0 && !severities.has(item.severity)) {
              return false;
            }
            if (sourceGroups.size > 0 && !sourceGroups.has(item.source_group)) {
              return false;
            }
            if (observationLayers.size > 0 && !observationLayers.has(item.observation_layer)) {
              return false;
            }
            if (matchSources.size > 0 && !matchSources.has(item.match_source)) {
              return false;
            }
            if (
              feeds.size > 0 &&
              !item.feed_hits.some((feedHit) => feeds.has(feedHit.feed))
            ) {
              return false;
            }
            if (typeof alertable === 'boolean' && item.alertable !== alertable) {
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
          disabled: state.threatFeedStatus.disabled,
        });
      },
    },
    {
      method: 'GET',
      pathname: '/api/v1/threats/feeds/status',
      handler: () => jsonResponse(state.threatFeedStatus),
    },
    {
      method: 'GET',
      pathname: '/api/v1/threats/silences',
      handler: () =>
        jsonResponse({
          items: state.threatSilences,
        }),
    },
  ];
}
