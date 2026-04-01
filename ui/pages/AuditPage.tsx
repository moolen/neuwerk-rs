import React, { useMemo } from "react";
import { PageLayout } from "../components/layout/PageLayout";
import { AuditFindingsTable } from "./audit/components/AuditFindingsTable";
import { AuditFiltersPanel } from "./audit/components/AuditFiltersPanel";
import { AuditNodeErrorsPanel } from "./audit/components/AuditNodeErrorsPanel";
import { auditFindingKey } from "./audit/threatAnnotations";
import { useAuditPage } from "./audit/useAuditPage";

export const AuditPage: React.FC = () => {
  const {
    items,
    loading,
    error,
    partial,
    nodes,
    nodeErrors,
    typeFilter,
    setTypeFilter,
    sourceGroup,
    setSourceGroup,
    load,
    threatAnnotations,
    performanceModeEnabled,
    performanceModeLoading,
    performanceModeError,
  } = useAuditPage();

  const filtered = useMemo(() => items, [items]);
  const activeFilterCount =
    (typeFilter === "all" ? 0 : 1) + (sourceGroup.trim() ? 1 : 0);
  const threatLinkedCount = filtered.filter(
    (item) => threatAnnotations[auditFindingKey(item)],
  ).length;
  const summaryCards = [
    {
      label: "Visible findings",
      value: String(filtered.length),
      detail:
        threatLinkedCount > 0
          ? `${threatLinkedCount} threat-linked`
          : "No threat pivots",
    },
    {
      label: "Node coverage",
      value:
        nodes.queried > 0
          ? `${nodes.responded}/${nodes.queried}`
          : performanceModeEnabled
            ? "Waiting"
            : "Unavailable",
      detail: partial ? "Partial cluster response" : "Cluster response settled",
    },
    {
      label: "Active filters",
      value: String(activeFilterCount),
      detail:
        activeFilterCount === 0
          ? "Showing the full deny review queue"
          : [
              typeFilter !== "all" ? typeFilter : null,
              sourceGroup.trim() || null,
            ]
              .filter(Boolean)
              .join(" · "),
    },
  ];

  return (
    <PageLayout
      title="Audit"
      description="Persisted policy deny findings across the cluster, aggregated and deduplicated for review."
    >
      <section
        className="rounded-[1.5rem] p-5 space-y-4"
        style={{
          background: "var(--bg-glass)",
          border: "1px solid var(--border-glass)",
          boxShadow: "var(--shadow-glass)",
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div
              className="text-[11px] uppercase tracking-[0.26em]"
              style={{ color: "var(--text-muted)" }}
            >
              Audit posture
            </div>
            <h2
              className="mt-2 text-lg font-semibold"
              style={{ color: "var(--text)" }}
            >
              Cluster deny review at a glance
            </h2>
            <p
              className="mt-1 text-sm max-w-[44rem]"
              style={{ color: "var(--text-secondary)" }}
            >
              Start with scope, coverage, and active filters before drilling
              into individual deny findings.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{
              background: "var(--bg-glass-subtle)",
              border: "1px solid var(--border-glass)",
              color: "var(--text-secondary)",
            }}
          >
            {performanceModeEnabled
              ? "Audit pipeline enabled"
              : "Audit pipeline disabled"}
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          {summaryCards.map((card) => (
            <div
              key={card.label}
              className="rounded-[1.15rem] p-4"
              style={{
                background: "var(--bg-glass-subtle)",
                border: "1px solid var(--border-glass)",
              }}
            >
              <div
                className="text-sm font-semibold"
                style={{ color: "var(--text)" }}
              >
                {card.label}
              </div>
              <div
                className="mt-2 text-2xl font-bold"
                style={{ color: "var(--text)" }}
              >
                {card.value}
              </div>
              <div
                className="mt-1 text-sm"
                style={{ color: "var(--text-secondary)" }}
              >
                {card.detail}
              </div>
            </div>
          ))}
        </div>
      </section>

      <AuditFiltersPanel
        typeFilter={typeFilter}
        sourceGroup={sourceGroup}
        loading={loading}
        disabled={!performanceModeEnabled}
        onTypeFilterChange={setTypeFilter}
        onSourceGroupChange={setSourceGroup}
        onRefresh={() => void load()}
      />

      {performanceModeError && (
        <div
          className="rounded-lg p-4"
          style={{
            background: "var(--yellow-bg, rgba(245, 158, 11, 0.12))",
            border: "1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))",
            color: "var(--text)",
          }}
        >
          {performanceModeError}
        </div>
      )}

      {!performanceModeLoading && !performanceModeEnabled && (
        <div
          className="rounded-lg p-4"
          style={{
            background: "var(--yellow-bg, rgba(245, 158, 11, 0.12))",
            border: "1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))",
            color: "var(--text)",
          }}
        >
          Performance mode is disabled. Audit is unavailable until it is
          re-enabled in Settings.
        </div>
      )}

      {error && (
        <div
          className="rounded-lg p-4"
          style={{
            background: "var(--red-bg)",
            border: "1px solid var(--red-border)",
            color: "var(--red)",
          }}
        >
          {error}
        </div>
      )}

      {partial && (
        <div
          className="rounded-lg p-4"
          style={{
            background: "var(--yellow-bg, rgba(245, 158, 11, 0.12))",
            border: "1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))",
            color: "var(--text)",
          }}
        >
          Partial results: {nodes.responded}/{nodes.queried} nodes responded.
        </div>
      )}

      <AuditNodeErrorsPanel nodeErrors={nodeErrors} />

      <AuditFindingsTable
        items={filtered}
        threatAnnotations={threatAnnotations}
      />
    </PageLayout>
  );
};
