import type {
  PolicyConfig,
  PolicyTelemetryResponse,
} from "../../types";
import { fetchJSON, fetchText } from "./transport";

export function buildPolicyTelemetryPath(): string {
  return "/policy/telemetry";
}

export async function getPolicy(): Promise<PolicyConfig> {
  return fetchJSON<PolicyConfig>("/policy");
}

export async function getPolicyYaml(): Promise<string> {
  return fetchText("/policy?format=yaml");
}

export async function updatePolicy(req: PolicyConfig): Promise<PolicyConfig> {
  return fetchJSON<PolicyConfig>("/policy", {
    method: "PUT",
    body: JSON.stringify(req),
  });
}

export async function getPolicyTelemetry(): Promise<PolicyTelemetryResponse> {
  return fetchJSON<PolicyTelemetryResponse>(buildPolicyTelemetryPath());
}
