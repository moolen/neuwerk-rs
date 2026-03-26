import { describe, expect, it, vi } from 'vitest';

import type { PolicyTelemetryResponse } from '../../types';
import { buildPolicyTelemetryPath } from '../../services/apiClient/policies';
import { loadPolicyTelemetryRemote } from './policyTelemetryRemote';

vi.mock('../../services/api', () => ({
  getPolicyTelemetry: vi.fn(),
}));

import * as api from '../../services/api';

describe('policyTelemetryRemote', () => {
  it('builds the policy telemetry path', () => {
    expect(buildPolicyTelemetryPath('policy-1')).toBe('/policies/policy-1/telemetry');
  });

  it('loads policy-scoped telemetry through the shared API surface', async () => {
    vi.mocked(api.getPolicyTelemetry).mockResolvedValue({
      items: [
        {
          source_group_id: 'apps',
          current_24h_hits: 120,
          previous_24h_hits: 100,
        },
      ],
      partial: true,
      node_errors: [{ node_id: 'node-b', error: 'timeout' }],
      nodes_queried: 3,
      nodes_responded: 2,
    } satisfies PolicyTelemetryResponse);

    const result = await loadPolicyTelemetryRemote('policy-1');

    expect(api.getPolicyTelemetry).toHaveBeenCalledWith('policy-1');
    expect(result.items[0]).toMatchObject({
      source_group_id: 'apps',
      current_24h_hits: 120,
      previous_24h_hits: 100,
    });
    expect(result.partial).toBe(true);
  });
});
