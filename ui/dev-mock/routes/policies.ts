import { jsonResponse, textResponse } from "../http";
import type { MockState } from "../state";
import type { MockRequest, MockRoute } from "../types";
import type { PolicyConfig, PolicyRecord } from "../../types";

function parseJsonBody(request: MockRequest): unknown {
  if (!request.body || request.body.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(request.body.toString("utf-8"));
  } catch {
    return undefined;
  }
}

function singletonPolicy(state: MockState): PolicyRecord | undefined {
  return state.policies[0];
}

export function createPolicyRoutes(state: MockState): MockRoute[] {
  return [
    {
      method: "GET",
      pathname: "/api/v1/policy",
      handler: (request) => {
        const policy = singletonPolicy(state);
        if (!policy) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }

        const format = new URL(
          request.url,
          "http://neuwerk.dev",
        ).searchParams.get("format");
        if (format === "yaml") {
          const yaml = [
            `default_policy: ${policy.policy.default_policy ?? "deny"}`,
            `source_groups: ${policy.policy.source_groups.length}`,
            "",
          ].join("\n");
          return textResponse(yaml, {
            headers: { "content-type": "application/yaml; charset=utf-8" },
          });
        }

        return jsonResponse(policy.policy);
      },
    },
    {
      method: "PUT",
      pathname: "/api/v1/policy",
      handler: (request) => {
        const payload = parseJsonBody(request) as PolicyConfig | undefined;
        if (!payload || !Array.isArray(payload.source_groups)) {
          return jsonResponse(
            { error: "Policy source_groups are required" },
            { status: 400 },
          );
        }

        const existing = singletonPolicy(state);
        const updated: PolicyRecord = {
          id: existing?.id ?? "policy-1",
          created_at: existing?.created_at ?? new Date().toISOString(),
          mode: "enforce",
          policy: payload,
        };
        if (existing) {
          state.policies[0] = updated;
        } else {
          state.policies.unshift(updated);
        }
        return jsonResponse(payload);
      },
    },
    {
      method: "GET",
      pathname: "/api/v1/policy/telemetry",
      handler: () => {
        const policy = state.policies[0];
        if (!policy) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }

        return jsonResponse({
          items: policy.policy.source_groups.map((group, index) => ({
            source_group_id: group.id,
            current_24h_hits: 150 + index * 11,
            previous_24h_hits: 90 + index * 7,
          })),
          partial: false,
          node_errors: [],
          nodes_queried: state.stats.cluster.node_count,
          nodes_responded: state.stats.cluster.node_count,
        });
      },
    },
  ];
}
