import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuditPage } from "../../AuditPage";
import { useAuditPage } from "../useAuditPage";

vi.mock("../useAuditPage", () => ({
  useAuditPage: vi.fn(),
}));

describe("AuditPage structure", () => {
  beforeEach(() => {
    vi.mocked(useAuditPage).mockReturnValue({
      items: [
        {
          finding_type: "dns_deny",
          policy_id: null,
          source_group: "homenet",
          hostname: "bad.example.com",
          dst_ip: null,
          dst_port: null,
          proto: null,
          fqdn: "bad.example.com",
          sni: null,
          icmp_type: null,
          icmp_code: null,
          query_type: null,
          first_seen: 1_700_000_000,
          last_seen: 1_700_000_010,
          count: 42,
          node_ids: ["node-a", "node-b"],
        },
      ],
      loading: false,
      error: null,
      partial: true,
      nodes: { queried: 3, responded: 2 },
      nodeErrors: [{ node_id: "node-c", error: "timeout" }],
      typeFilter: "dns_deny",
      setTypeFilter: () => {},
      sourceGroup: "homenet",
      setSourceGroup: () => {},
      load: async () => {},
      threatAnnotations: {},
      performanceModeEnabled: true,
      performanceModeLoading: false,
      performanceModeError: null,
    });
  });

  it("renders triage landmarks above the findings table", () => {
    const html = renderToStaticMarkup(<AuditPage />);

    expect(html).toContain("Visible findings");
    expect(html).toContain("Node coverage");
    expect(html).toContain("Active filters");
    expect(html).toContain("Review queue");
  });
});
