import { describe, expect, it } from "vitest";

import { createMockRouter } from "../router";

function createTestMockServer() {
  const router = createMockRouter();

  async function request(
    method: string,
    url: string,
    body?: unknown,
  ): Promise<NonNullable<Awaited<ReturnType<typeof router.handle>>>> {
    const response = await router.handle({
      method,
      url,
      headers: body ? { "content-type": "application/json" } : {},
      body: body ? Buffer.from(JSON.stringify(body)) : undefined,
    });
    if (!response) {
      throw new Error(`No response for ${method} ${url}`);
    }
    return response;
  }

  async function requestJson<T>(
    method: string,
    url: string,
    body?: unknown,
  ): Promise<T> {
    const response = await request(method, url, body);
    expect(response.status).toBeLessThan(400);
    expect(response.kind).toBe("json");
    return response.json as T;
  }

  async function requestText(method: string, url: string): Promise<string> {
    const response = await request(method, url);
    expect(response.status).toBeLessThan(400);
    expect(response.kind).toBe("text");
    return response.text ?? "";
  }

  async function requestBlob(
    method: string,
    url: string,
  ): Promise<{
    body: Uint8Array;
    headers: Record<string, string>;
  }> {
    const response = await request(method, url);
    expect(response.status).toBeLessThan(400);
    expect(response.kind).toBe("blob");
    return {
      body: response.body ?? new Uint8Array(),
      headers: response.headers,
    };
  }

  return { request, requestJson, requestText, requestBlob };
}

describe("dev mock CRUD domain routes", () => {
  it("bootstraps a singleton policy for fresh reads", async () => {
    const server = createTestMockServer();

    const fetched = await server.requestJson<{
      default_policy?: string;
      source_groups: Array<{ id: string }>;
    }>("GET", "/api/v1/policy");
    const telemetry = await server.requestJson<{
      items: unknown[];
      partial: boolean;
    }>("GET", "/api/v1/policy/telemetry");

    expect(fetched).toEqual({
      default_policy: "deny",
      source_groups: [],
    });
    expect(telemetry).toMatchObject({
      items: [],
      partial: false,
    });
  });

  it("persists singleton policy updates in memory", async () => {
    const server = createTestMockServer();

    const updated = await server.requestJson<{
      default_policy?: string;
      source_groups: Array<{ id: string }>;
    }>("PUT", "/api/v1/policy", {
      default_policy: "deny",
      source_groups: [
        {
          id: "singleton-group",
          mode: "enforce",
          sources: {
            cidrs: ["10.0.0.0/24"],
          },
          rules: [],
        },
      ],
    });

    const fetched = await server.requestJson<{
      default_policy?: string;
      source_groups: Array<{ id: string }>;
    }>("GET", "/api/v1/policy");
    const yaml = await server.requestText("GET", "/api/v1/policy?format=yaml");
    const telemetry = await server.requestJson<{
      items: unknown[];
      partial: boolean;
    }>("GET", "/api/v1/policy/telemetry");

    expect(updated.default_policy).toBe("deny");
    expect(updated.source_groups).toHaveLength(1);
    expect(fetched.source_groups[0]?.id).toBe("singleton-group");
    expect(yaml).toContain("default_policy: deny");
    expect(yaml).toContain("source_groups: 1");
    expect(telemetry).toMatchObject({
      items: expect.any(Array),
      partial: expect.any(Boolean),
    });
  });

  it("persists integrations edits and deletes in list results", async () => {
    const server = createTestMockServer();
    const created = await server.requestJson<{
      name: string;
      token_configured: boolean;
    }>("POST", "/api/v1/integrations", {
      name: "cluster-a",
      kind: "kubernetes",
      api_server_url: "https://cluster-a.internal",
      ca_cert_pem: "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----",
      service_account_token: "token-a",
    });

    const updated = await server.requestJson<{
      name: string;
      api_server_url: string;
    }>("PUT", "/api/v1/integrations/cluster-a", {
      api_server_url: "https://cluster-a-updated.internal",
      ca_cert_pem: "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----",
      service_account_token: "token-b",
    });

    const list = await server.requestJson<
      Array<{ name: string; api_server_url: string }>
    >("GET", "/api/v1/integrations");

    expect(created.token_configured).toBe(true);
    expect(updated.api_server_url).toBe("https://cluster-a-updated.internal");
    expect(list).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "cluster-a",
          api_server_url: "https://cluster-a-updated.internal",
        }),
      ]),
    );

    const deleteResponse = await server.request(
      "DELETE",
      "/api/v1/integrations/cluster-a",
    );
    const afterDeleteRead = await server.request(
      "GET",
      "/api/v1/integrations/cluster-a",
    );
    const listAfterDelete = await server.requestJson<Array<{ name: string }>>(
      "GET",
      "/api/v1/integrations",
    );
    expect(deleteResponse.status).toBeLessThan(400);
    expect(afterDeleteRead.status).toBe(404);
    expect(
      listAfterDelete.some((integration) => integration.name === "cluster-a"),
    ).toBe(false);
  });

  it("creates updates and disables service accounts with token lifecycle", async () => {
    const server = createTestMockServer();
    const account = await server.requestJson<{
      id: string;
      name: string;
      status: string;
    }>("POST", "/api/v1/service-accounts", {
      name: "automation",
      description: "CI automation",
      role: "admin",
    });

    const updated = await server.requestJson<{
      id: string;
      name: string;
      status: string;
    }>("PUT", `/api/v1/service-accounts/${account.id}`, {
      name: "automation-renamed",
      description: "CI automation updated",
      role: "readonly",
    });

    const tokenResponse = await server.requestJson<{
      token: string;
      token_meta: { id: string; status: string; role: string };
    }>("POST", `/api/v1/service-accounts/${account.id}/tokens`, {
      name: "build-token",
      role: "readonly",
      eternal: true,
    });
    expect(tokenResponse.token).toContain(".");

    const tokens = await server.requestJson<
      Array<{ id: string; status: string }>
    >("GET", `/api/v1/service-accounts/${account.id}/tokens`);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: tokenResponse.token_meta.id,
          status: "active",
        }),
      ]),
    );

    const revokeTokenResponse = await server.request(
      "DELETE",
      `/api/v1/service-accounts/${account.id}/tokens/${tokenResponse.token_meta.id}`,
    );
    expect(revokeTokenResponse.status).toBeLessThan(400);

    const disableResponse = await server.request(
      "DELETE",
      `/api/v1/service-accounts/${account.id}`,
    );
    expect(disableResponse.status).toBeLessThan(400);

    const list = await server.requestJson<
      Array<{ id: string; status: string; name: string }>
    >("GET", "/api/v1/service-accounts");

    expect(updated.name).toBe("automation-renamed");
    expect(list).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: account.id,
          status: "disabled",
        }),
      ]),
    );
  });

  it("supports SSO provider create update test and delete", async () => {
    const server = createTestMockServer();
    const created = await server.requestJson<{
      id: string;
      name: string;
      enabled: boolean;
    }>("POST", "/api/v1/settings/sso/providers", {
      name: "Local OIDC",
      kind: "generic-oidc",
      enabled: true,
      issuer_url: "https://sso.example.test",
      client_id: "dev-client",
      client_secret: "dev-secret",
    });

    const updated = await server.requestJson<{
      id: string;
      name: string;
      enabled: boolean;
    }>("PUT", `/api/v1/settings/sso/providers/${created.id}`, {
      name: "Local OIDC Updated",
      enabled: false,
    });

    const testResult = await server.requestJson<{
      ok: boolean;
      details: string;
    }>("POST", `/api/v1/settings/sso/providers/${created.id}/test`);
    expect(testResult.ok).toBe(true);

    const deleteResponse = await server.request(
      "DELETE",
      `/api/v1/settings/sso/providers/${created.id}`,
    );
    expect(deleteResponse.status).toBeLessThan(400);

    const providers = await server.requestJson<
      Array<{ id: string; name: string }>
    >("GET", "/api/v1/settings/sso/providers");

    expect(updated.name).toBe("Local OIDC Updated");
    expect(providers.some((provider) => provider.id === created.id)).toBe(
      false,
    );
  });

  it("returns 400 for malformed SSO update payloads instead of crashing", async () => {
    const server = createTestMockServer();
    const created = await server.requestJson<{ id: string }>(
      "POST",
      "/api/v1/settings/sso/providers",
      {
        name: "Strict SSO",
        kind: "generic-oidc",
        enabled: true,
        issuer_url: "https://strict.example.test",
        client_id: "strict-client",
        client_secret: "strict-secret",
      },
    );

    const malformedNameResponse = await server.request(
      "PUT",
      `/api/v1/settings/sso/providers/${created.id}`,
      { name: null },
    );
    const malformedClientIdResponse = await server.request(
      "PUT",
      `/api/v1/settings/sso/providers/${created.id}`,
      { client_id: null },
    );

    expect(malformedNameResponse.status).toBe(400);
    expect(malformedClientIdResponse.status).toBe(400);
  });

  it("writes performance and threat-intel toggles and handles TLS CA workflows", async () => {
    const server = createTestMockServer();
    const perf = await server.requestJson<{ enabled: boolean; source: string }>(
      "PUT",
      "/api/v1/settings/performance-mode",
      {
        enabled: false,
      },
    );
    const threat = await server.requestJson<{
      enabled: boolean;
      source: string;
    }>("PUT", "/api/v1/settings/threat-intel", {
      enabled: false,
    });
    const tlsUpdated = await server.requestJson<{
      configured: boolean;
      source: string;
    }>("PUT", "/api/v1/settings/tls-intercept-ca", {
      ca_cert_pem: "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----",
      ca_key_pem: "-----BEGIN PRIVATE KEY-----\nD\n-----END PRIVATE KEY-----",
    });
    const tlsGenerated = await server.requestJson<{
      configured: boolean;
      source: string;
    }>("POST", "/api/v1/settings/tls-intercept-ca/generate");
    const cert = await server.requestText(
      "GET",
      "/api/v1/settings/tls-intercept-ca/cert",
    );

    expect(perf).toMatchObject({ enabled: false, source: "local" });
    expect(threat).toMatchObject({ enabled: false, source: "local" });
    expect(tlsUpdated).toMatchObject({ configured: true, source: "local" });
    expect(tlsGenerated).toMatchObject({ configured: true, source: "local" });
    expect(cert).toContain("BEGIN CERTIFICATE");
  });

  it("returns a synthetic cluster sysdump blob with filename metadata", async () => {
    const server = createTestMockServer();
    const response = await server.requestBlob(
      "POST",
      "/api/v1/support/sysdump/cluster",
    );
    const decoded = Buffer.from(response.body).toString("utf-8");

    expect(response.headers["content-disposition"]).toContain("filename=");
    expect(decoded).toContain("mock");
  });
});
