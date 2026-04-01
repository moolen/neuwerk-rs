import type { PolicyTelemetryResponse } from "../../types";
import { getPolicyTelemetry } from "../../services/api";

export async function loadPolicyTelemetryRemote(): Promise<PolicyTelemetryResponse> {
  return getPolicyTelemetry();
}
