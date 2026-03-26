import type { PolicyTelemetryResponse } from '../../types';
import { getPolicyTelemetry } from '../../services/api';

export async function loadPolicyTelemetryRemote(policyId: string): Promise<PolicyTelemetryResponse> {
  return getPolicyTelemetry(policyId);
}
