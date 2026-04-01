import { jsonResponse, textResponse } from "../http";
import type { MockState } from "../state";
import type { MockRequest, MockRoute } from "../types";
import type { PolicyCreateRequest, PolicyRecord } from "../../types";

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

function readPolicyId(pathname: string): string | null {
  const prefix = "/api/v1/policies/";
  if (!pathname.startsWith(prefix)) {
    return null;
  }
  const tail = pathname.slice(prefix.length);
  if (!tail || tail.includes("/")) {
    return null;
  }
  try {
    return decodeURIComponent(tail);
  } catch {
    return tail;
  }
}

function findPolicy(state: MockState, id: string): PolicyRecord | undefined {
  return state.policies.find((entry) => entry.id === id);
}

export function createPolicyRoutes(state: MockState): MockRoute[] {
  let nextId = state.policies.length + 1;

  return [
    {
      method: "GET",
      pathname: "/api/v1/policies",
      handler: () => jsonResponse(state.policies),
    },
    {
      method: "POST",
      pathname: "/api/v1/policies",
      handler: (request) => {
        const payload = parseJsonBody(request) as
          | PolicyCreateRequest
          | undefined;
        if (
          !payload ||
          !payload.policy ||
          !Array.isArray(payload.policy.source_groups)
        ) {
          return jsonResponse(
            { error: "Policy source_groups are required" },
            { status: 400 },
          );
        }
        if (!payload.mode) {
          return jsonResponse(
            { error: "Policy mode is required" },
            { status: 400 },
          );
        }

        const created: PolicyRecord = {
          id: `policy-${nextId++}`,
          created_at: new Date().toISOString(),
          name: payload.name?.trim() || undefined,
          mode: payload.mode,
          policy: payload.policy,
        };
        state.policies.unshift(created);
        return jsonResponse(created, { status: 201 });
      },
    },
    {
      method: "GET",
      pathname: "/api/v1/policies/:id",
      handler: (request) => {
        const id = readPolicyId(request.pathname);
        if (!id) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }
        const policy = findPolicy(state, id);
        if (!policy) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }

        const format = new URL(
          request.url,
          "http://neuwerk.dev",
        ).searchParams.get("format");
        if (format === "yaml") {
          const yaml = [
            `id: ${policy.id}`,
            `mode: ${policy.mode}`,
            `name: ${policy.name ?? ""}`,
            "policy:",
            `  source_groups: ${policy.policy.source_groups.length}`,
            "",
          ].join("\n");
          return textResponse(yaml, {
            headers: { "content-type": "application/yaml; charset=utf-8" },
          });
        }

        return jsonResponse(policy);
      },
    },
    {
      method: "PUT",
      pathname: "/api/v1/policies/:id",
      handler: (request) => {
        const id = readPolicyId(request.pathname);
        if (!id) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }
        const existing = findPolicy(state, id);
        if (!existing) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }
        const payload = parseJsonBody(request) as
          | PolicyCreateRequest
          | undefined;
        if (
          !payload ||
          !payload.policy ||
          !Array.isArray(payload.policy.source_groups)
        ) {
          return jsonResponse(
            { error: "Policy source_groups are required" },
            { status: 400 },
          );
        }
        if (!payload.mode) {
          return jsonResponse(
            { error: "Policy mode is required" },
            { status: 400 },
          );
        }

        const updated: PolicyRecord = {
          ...existing,
          name: payload.name?.trim() || undefined,
          mode: payload.mode,
          policy: payload.policy,
        };
        const index = state.policies.findIndex((item) => item.id === id);
        state.policies[index] = updated;
        return jsonResponse(updated);
      },
    },
    {
      method: "DELETE",
      pathname: "/api/v1/policies/:id",
      handler: (request) => {
        const id = readPolicyId(request.pathname);
        if (!id) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }
        const index = state.policies.findIndex((item) => item.id === id);
        if (index < 0) {
          return jsonResponse({ error: "Not found" }, { status: 404 });
        }
        state.policies.splice(index, 1);
        return jsonResponse(undefined, { status: 204 });
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
