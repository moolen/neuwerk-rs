import { useEffect, useState } from "react";
import {
  getAuditFindings,
  getPerformanceModeStatus,
  getThreatFindings,
} from "../../services/api";
import type { AuditFinding, AuditFindingType } from "../../types";
import {
  buildAuditThreatAnnotations,
  type AuditThreatAnnotation,
} from "./threatAnnotations";

export function useAuditPage() {
  const [items, setItems] = useState<AuditFinding[]>([]);
  const [threatAnnotations, setThreatAnnotations] = useState<
    Record<string, AuditThreatAnnotation>
  >({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partial, setPartial] = useState(false);
  const [nodes, setNodes] = useState<{ queried: number; responded: number }>({
    queried: 0,
    responded: 0,
  });
  const [nodeErrors, setNodeErrors] = useState<
    Array<{ node_id: string; error: string }>
  >([]);
  const [typeFilter, setTypeFilter] = useState<AuditFindingType | "all">("all");
  const [sourceGroup, setSourceGroup] = useState("");
  const [performanceModeEnabled, setPerformanceModeEnabled] = useState(true);
  const [performanceModeLoading, setPerformanceModeLoading] = useState(true);
  const [performanceModeError, setPerformanceModeError] = useState<
    string | null
  >(null);

  const load = async () => {
    if (!performanceModeEnabled) {
      setLoading(false);
      setItems([]);
      setPartial(false);
      setNodes({ queried: 0, responded: 0 });
      setNodeErrors([]);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const [response, threatResponse] = await Promise.all([
        getAuditFindings({
          finding_type: typeFilter === "all" ? [] : [typeFilter],
          source_group: sourceGroup.trim() ? [sourceGroup.trim()] : [],
          limit: 1000,
        }),
        getThreatFindings({ limit: 1000 }).catch((err) => {
          console.error(
            "Failed to load threat annotations for audit page:",
            err,
          );
          return null;
        }),
      ]);
      setItems(response.items);
      setPartial(response.partial);
      setNodes({
        queried: response.nodes_queried,
        responded: response.nodes_responded,
      });
      setNodeErrors(response.node_errors ?? []);
      setThreatAnnotations(
        threatResponse
          ? buildAuditThreatAnnotations(response.items, threatResponse.items)
          : {},
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load audit findings",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      try {
        setPerformanceModeLoading(true);
        setPerformanceModeError(null);
        const status = await getPerformanceModeStatus();
        if (cancelled) {
          return;
        }
        setPerformanceModeEnabled(status.enabled);
        if (status.enabled) {
          await load();
        } else {
          setLoading(false);
        }
      } catch (err) {
        if (cancelled) {
          return;
        }
        setPerformanceModeEnabled(true);
        setPerformanceModeError(
          err instanceof Error
            ? err.message
            : "Failed to load performance mode status",
        );
        await load();
      } finally {
        if (!cancelled) {
          setPerformanceModeLoading(false);
        }
      }
    };
    void init();
    return () => {
      cancelled = true;
    };
  }, []);

  return {
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
  };
}
